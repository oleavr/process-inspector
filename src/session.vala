namespace ProcessInspector {
	public interface Session : Object {
		public static Session open (int pid, NetworkService network, Cancellable? cancellable = null) throws Error {
			return DarwinSession.open (pid, network, cancellable);
		}

		public abstract async Gee.ArrayList<Thread> enumerate_threads (Cancellable? cancellable = null) throws Error;
	}

	public errordomain SessionError {
		FAILED,
	}

	public class Thread : Object {
		public string? name {
			get;
			private set;
		}

		public Gee.ArrayList<Frame> backtrace {
			get;
			private set;
		}

		public Thread (string? name, Gee.ArrayList<Frame> backtrace) {
			this.name = name;
			this.backtrace = backtrace;
		}

		public class Frame {
			public Gum.Address address;
			public Gum.Address stack_location;

			public string? module_name;
			public string? symbol_name;

			public string? file_name;
			public uint line_number;

			public Frame (Gum.Address address, Gum.Address stack_location) {
				this.address = address;
				this.stack_location = stack_location;
			}

			public void symbolicate (Gum.DebugSymbolDetails details) {
				module_name = details.module_name;
				symbol_name = details.symbol_name;

				var file_name = details.file_name;
				if (file_name.length > 0) {
					this.file_name = file_name;
					this.line_number = details.line_number;
				}
			}
		}
	}
}
