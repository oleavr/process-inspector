class ProcessInspector.DarwinSession : Object, Initable, Session {
	public int pid {
		get;
		construct;
	}

	public NetworkService network {
		get;
		construct;
	}

	private const uint32 THREAD_MAGIC = 0x54485244;
	private const uint32 MACHO32_MAGIC = (uint32) 0xfeedface;
	private const uint32 MACHO64_MAGIC = (uint32) 0xfeedfacf;

	private Gum.DarwinPort task;
	private Gum.CpuType cpu_type;
	private uint page_size;
	private Gum.Darwin.Symbolicator symbolicator;

	private Gee.ArrayList<ManuallyMappedDylib> manually_mapped_dylibs = new Gee.ArrayList<ManuallyMappedDylib> ();

	public static DarwinSession open (int pid, NetworkService network, Cancellable? cancellable = null) throws Error {
		var session = new DarwinSession (pid, network);
		session.init (cancellable);
		return session;
	}

	public DarwinSession (int pid, NetworkService network) {
		Object (pid: pid, network: network);
	}

	construct {
		ensure_platform_initialized ();
	}

	public bool init (Cancellable? cancellable) throws Error {
		task = task_for_pid (pid);

		if (!Gum.Darwin.cpu_type_from_pid (pid, out cpu_type))
			throw new SessionError.FAILED ("Failed to query CPU type");

		if (!Gum.Darwin.query_page_size (task, out page_size))
			throw new SessionError.FAILED ("Failed to query page size");

		try {
			symbolicator = new Gum.Darwin.Symbolicator.with_task (task);
		} catch (Error e) {
			throw new SessionError.FAILED ("%s", e.message);
		}

		return true;
	}

	public async Gee.ArrayList<Thread> enumerate_threads (Cancellable? cancellable) throws Error {
		var threads = new Gee.ArrayList<Thread> ();

		Gum.Darwin.enumerate_threads (task, details => {
			Gum.Arm64CpuContext * context = (Gum.Arm64CpuContext *) &details.cpu_context;

			threads.add (new Thread (
				query_thread_name ((Gum.DarwinPort) details.id),
				details.state,
				generate_backtrace (context)
			));

			return true;
		});

		foreach (var thread in threads) {
			foreach (var frame in thread.backtrace) {
				yield try_symbolicate (frame, cancellable);
			}
		}

		return threads;
	}

	private async bool try_symbolicate (Thread.Frame frame, Cancellable? cancellable) {
		Gum.DebugSymbolDetails details;

		if (symbolicator.details_from_address (frame.address, out details)) {
			frame.symbolicate (details);
			return true;
		}

		Gum.Address caller;
		if (try_parse_interceptor_frame (frame, out caller)) {
			frame.address = caller;

			if (symbolicator.details_from_address (frame.address, out details)) {
				frame.symbolicate (details);
				return true;
			}
		}

		ManuallyMappedDylib? dylib = yield try_find_manually_mapped_dylib (frame.address, cancellable);
		if (dylib == null)
			return false;

		var module = dylib.module;
		var dylib_symbolicator = dylib.symbolicator;
		if (dylib_symbolicator != null && dylib_symbolicator.details_from_address (frame.address - module.slide, out details)) {
			frame.symbolicate (details);
			frame.module_name = Path.get_basename (module.name);
			return true;
		}

		var name = module.name;
		if (name != null)
			frame.module_name = Path.get_basename (name);
		else
			frame.module_name = module.uuid;

		var module_base = module.base_address;
		frame.symbol_name = ("0x%" + uint64.FORMAT_MODIFIER + "x").printf (frame.address - module_base);

		return true;
	}

	private async ManuallyMappedDylib? try_find_manually_mapped_dylib (Gum.Address address, Cancellable? cancellable) {
		foreach (var candidate in manually_mapped_dylibs) {
			if (candidate.module.is_address_in_text_section (address))
				return candidate;
		}

		var module = find_closest_module (address);
		if (module == null)
			return null;

		var dwarf_name = module.uuid + ".dwarf";
		var dwarf_path = Path.build_filename (Environment.get_home_dir (), dwarf_name);
		bool have_dwarf = FileUtils.test (dwarf_path, EXISTS);
		if (!have_dwarf && module.name.ascii_down ().index_of ("frida") != -1) {
			try {
				var tmp_file = yield network.download ("https://build.frida.re/symbols/ios/" + dwarf_name, cancellable);
				FileUtils.rename (tmp_file.get_path (), dwarf_path);
				have_dwarf = true;
			} catch (Error e) {
				warning ("Failed to download: %s", e.message);
			}
		}

		Gum.Darwin.Symbolicator? symbolicator = null;
		if (have_dwarf) {
			try {
				symbolicator = new Gum.Darwin.Symbolicator.with_path (dwarf_path, cpu_type);
			} catch (Error e) {
				FileUtils.unlink (dwarf_path);
			}
		}

		var dylib = new ManuallyMappedDylib (module, symbolicator);
		manually_mapped_dylibs.add (dylib);

		return dylib;
	}

	private class ManuallyMappedDylib : Object {
		public Gum.DarwinModule module {
			get;
			construct;
		}

		public Gum.Darwin.Symbolicator? symbolicator {
			get;
			construct;
		}

		public ManuallyMappedDylib (Gum.DarwinModule module, Gum.Darwin.Symbolicator? symbolicator) {
			Object (module: module, symbolicator: symbolicator);
		}
	}

	private const uint32[] TRAMPOLINE_EPILOG_SIGNATURE = {
		(uint32) 0x910043ff, // add sp, sp, 0x10
		(uint32) 0xa8c103e1, // ldp x1, x0, [sp], 0x10
		(uint32) 0xa8c10be1, // ldp x1, x2, [sp], 0x10
		(uint32) 0xa8c113e3, // ldp x3, x4, [sp], 0x10
	};

	private bool try_parse_interceptor_frame (Thread.Frame frame, out Gum.Address caller) {
		caller = 0;

		uint8[]? trampoline_bytes = Gum.Darwin.read (task, frame.address, TRAMPOLINE_EPILOG_SIGNATURE.length * sizeof (uint32));
		if (trampoline_bytes == null)
			return false;

		if (Memory.cmp (trampoline_bytes, TRAMPOLINE_EPILOG_SIGNATURE, trampoline_bytes.length) != 0)
			return false;

		Gum.Address cpu_context_start = frame.stack_location + 16 + 8;
		Gum.Address x17_start = cpu_context_start + (19 * 8);
		Gum.Address function_context;
		if (!try_read_pointer (x17_start, out function_context))
			return false;

		Gum.Address function_address;
		if (!try_read_pointer (function_context, out function_address))
			return false;

		caller = function_address;

		return true;
	}

	private Gum.DarwinModule? find_closest_module (Gum.Address address) {
		Gum.Address cur_region = round_down_to_4k_boundary (address);
		while (true) {
			uint8[]? chunk = Gum.Darwin.read (task, cur_region, 4);
			if (chunk == null)
				return null;

			uint32 val = *((uint32 *) chunk);
			if (val == MACHO32_MAGIC || val == MACHO64_MAGIC) {
				try {
					var module = new Gum.DarwinModule.from_memory (null, task, cur_region);
					if (module.name != null && module.uuid != null)
						return module;
				} catch (Error e) {
				}
			}

			cur_region -= 4096;
		}
	}

	private Gee.ArrayList<Thread.Frame> generate_backtrace (Gum.Arm64CpuContext * context) {
		var result = new Gee.ArrayList<Thread.Frame> ();

		result.add (new Thread.Frame (context->lr, context->sp));

		Gum.Address current = context->fp;
		var stack = find_stack_bounds (context->sp);
		while (current >= stack.bottom && current < stack.top && frame_pointer_is_aligned (current)) {
			uint8[]? frame_bytes = Gum.Darwin.read (task, current, 16);
			if (frame_bytes == null)
				break;

			uint64 * frame = (uint64 *) frame_bytes;
			Gum.Address next = frame[0];
			Gum.Address return_address = frame[1];

			if (next == 0 || return_address == 0)
				break;
			result.add (new Thread.Frame (return_address, current));

			if (next <= current)
				break;
			current = next;
		}

		return result;
	}

	private static bool frame_pointer_is_aligned (Gum.Address fp) {
		return (fp & 1) == 0;
	}

	private StackBounds find_stack_bounds (Gum.Address sp) {
		Gum.Address start_page = round_down_to_page_boundary (sp);
		Gum.Address end_page = start_page + (1024 * page_size);

		Gum.Address cur_region = (start_page + 4095) & ~(Gum.Address) 4095;
		while (cur_region != end_page) {
			uint8[]? chunk = Gum.Darwin.read (task, cur_region, 4);
			if (chunk == null)
				return StackBounds (sp, round_down_to_page_boundary (cur_region));

			uint32 * chunk_ptr = (uint32 *) chunk;
			if (*chunk_ptr == THREAD_MAGIC)
				return StackBounds (sp, cur_region);

			cur_region += 4096;
		}

		return StackBounds (sp, cur_region);
	}

	private Gum.Address round_down_to_page_boundary (Gum.Address address) {
		return address & ~((Gum.Address) (page_size - 1));
	}

	private static Gum.Address round_down_to_4k_boundary (Gum.Address address) {
		return (address + 4095) & ~(Gum.Address) 4095;
	}

	private bool try_read_pointer (Gum.Address address, out Gum.Address val) {
		uint8[]? bytes = Gum.Darwin.read (task, address, sizeof (uint64));
		if (bytes == null) {
			val = 0;
			return false;
		}

		val = *((uint64 *) bytes);
		return true;
	}

	private static Gum.DarwinPort task_for_pid (int pid) throws SessionError {
		Gum.DarwinPort task;
		var result = Gum.Darwin.task_for_pid (Gum.Darwin.mach_task_self (), pid, out task);
		if (result != SUCCESS)
			throw new SessionError.FAILED ("task_for_pid() failed: %d", result);
		return task;
	}

	private static extern string? query_thread_name (Gum.DarwinPort thread);

	private struct StackBounds {
		public Gum.Address bottom;
		public Gum.Address top;

		public StackBounds (Gum.Address bottom, Gum.Address top) {
			this.bottom = bottom;
			this.top = top;
		}
	}

	private static Once platform_initialized;

	private static void ensure_platform_initialized () {
		platform_initialized.once (() => {
			var cf = dlopen ("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", 9);
			assert (cf != null);

			if (!FileUtils.test (ELECTRA_JAILBREAKD_LIBRARY, EXISTS))
				return true;

			var module = Module.open (ELECTRA_JAILBREAKD_LIBRARY, LAZY);
			assert (module != null);

			void * entitle_now_address;
			var found = module.symbol ("jb_oneshot_entitle_now", out entitle_now_address);
			assert (found);

			ElectraEntitleFunc entitle_now = (ElectraEntitleFunc) entitle_now_address;
			entitle_now (Posix.getpid (), ELECTRA_FLAG_PLATFORMIZE);

			return true;
		});
	}

	[CCode (cname = "dlopen")]
	private static extern void * dlopen (string path, int mode);

	private const string ELECTRA_JAILBREAKD_LIBRARY = "/usr/lib/libjailbreak.dylib";
	private const int ELECTRA_FLAG_PLATFORMIZE = (1 << 1);
	[CCode (has_target = false)]
	private delegate int ElectraEntitleFunc (Posix.pid_t pid, uint32 what);
}
