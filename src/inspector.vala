namespace ProcessInspector {
	private static int target_pid = -1;

	const OptionEntry[] options = {
		{ "pid", 'p', 0, OptionArg.INT, ref target_pid, null, "PID" },
		{ null }
	};

	private static int main (string[] args) {
		Gum.init ();
		GIOOpenSSL.register ();

		try {
			var ctx = new OptionContext ();
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (target_pid == -1) {
			printerr ("PID must be specified\n");
			return 2;
		}

		var app = new Application (target_pid);

		return app.run ();
	}

	public class Application : Object {
		public int target_pid {
			get;
			construct;
		}

		private int exit_code;
		private MainLoop loop = new MainLoop ();
		private Cancellable cancellable = new Cancellable ();

		private NetworkService network = new NetworkService ();

		public Application (int target_pid) {
			Object (target_pid: target_pid);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			add_stop_handler (Posix.Signal.INT);
			add_stop_handler (Posix.Signal.TERM);

			exit_code = 0;

			loop.run ();

			return exit_code;
		}

		private async void start () {
			try {
				var session = Session.open (target_pid, network, cancellable);

				var threads = yield session.enumerate_threads (cancellable);
				uint thread_index = 0;
				var thread_state_enum = (EnumClass) typeof (Gum.ThreadState).class_ref ();
				foreach (var thread in threads) {
					var description = new StringBuilder ();

					if (thread_index > 0)
						description.append_c ('\n');

					description.append_printf ("Thread %u", thread_index);
					var name = thread.name;
					if (name != null) {
						description.append_printf (" (%s)", name);
					}
					description.append_printf (" [%s]", thread_state_enum.get_value (thread.state).value_nick);
					description.append_c ('\n');

					uint frame_index = 0;
					foreach (var frame in thread.backtrace) {
						description.append_printf ("%-2u  %-30s  ",
							frame_index,
							(frame.module_name != null) ? frame.module_name : "???"
						);

						if (frame.symbol_name != null)
							description.append (frame.symbol_name);
						else
							description.append_printf ("0x%" + uint64.FORMAT_MODIFIER + "x", frame.address);

						var file_name = frame.file_name;
						if (file_name != null)
							description.append_printf (" (%s:%u)", file_name, frame.line_number);

						description.append_c ('\n');

						frame_index++;
					}

					stdout.write (description.str.data);

					thread_index++;
				}

				loop.quit ();
			} catch (Error e) {
				printerr ("ERROR: %s\n", e.message);
				exit_code = 1;
				loop.quit ();
			}
		}

		private void add_stop_handler (int signum) {
			var source = new Unix.SignalSource (signum);
			source.set_callback (on_stop_request);
			source.attach ();
		}

		private bool on_stop_request () {
			cancellable.cancel ();
			return false;
		}
	}
}
