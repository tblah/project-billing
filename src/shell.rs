//! For the interactive shells used in main.rs

/*  This file is part of project-net.
    project-net is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    project-net is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with project-net.  If not, see http://www.gnu.org/licenses/.*/

use std::collections::HashMap;
use std::process::exit;
use std::mem::drop;
use std::io;
use std::io::Write;

struct CommandInfo<T> {
    closure: Box<Fn(&mut T, Vec<String>)>,
    help_string: String,
    help_name: String,
}

pub struct InteractiveShell<T> where T: 'static {
    my_name: String,
    shared_state: T,
    commands: HashMap<String, CommandInfo<T>>,
}

impl<T> InteractiveShell<T> {
    pub fn new<S: ToString>(my_name: S, shared_state: T) -> Self {
        InteractiveShell {
            my_name: my_name.to_string(),
            shared_state: shared_state,
            commands: HashMap::new(),
        }
    }
            
    pub fn register_command<S1, S2, S3>(&mut self, name: S1, help_name: S2, help_string: S3,
                                        closure: Box<Fn(&mut T, Vec<String>)>)
                                        where S1: ToString, S2: ToString, S3: ToString {
        let info = CommandInfo {
            closure: closure,
            help_string: help_string.to_string(),
            help_name: help_name.to_string(),
        };

        self.commands.insert(name.to_string(), info);
    }

    pub fn start(&mut self) {
        fn complain_arg<T>(arg: &Vec<T>) {
            if !(arg.is_empty()) {
                println!("This command did not require an argument");
            }
        }

        // common commands
        fn exit_command<T>(shared: &mut T, args: Vec<String>) {
            complain_arg(&args);
            println!("Goodbye");
            drop(shared);
            exit(0); // success
        }

        self.register_command("exit", "exit",  "Closes the program", Box::new(exit_command));

        // copy suitable to be moved into help_command
        let mut help_info = HashMap::new();
        for val in self.commands.values() {
            help_info.insert(val.help_name.clone(), val.help_string.clone());
        }

        // manually add help because it is not registered as a command yet
        help_info.insert("help".to_string(), "Display this help message".to_string());
        
        let help_command = move |shared: &mut T, args: Vec<String>| {
            let _ = shared; // suppress unused warning (#[ignore()] does not seem to work on closures)
            complain_arg(&args);
            println!("Usage:");
            println!("Command\t\tDescription\n");
            for (name, help) in help_info.iter() {
                println!("{}\t\t{}", name, help);
            }
        };

        self.register_command("help", "help", "Display this help message", Box::new(help_command));

        // repl
        loop {
            print!("{}> ", self.my_name);
            io::stdout().flush().unwrap();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_err() {
                println!("Error reading from stdin. Exiting.");
                drop(&mut self.shared_state);
                exit(1); // failure
            }

            let mut iter = input.split_whitespace();
            let command_name = iter.next().unwrap_or("");
            match self.commands.get(command_name) {
                Some(v) => {
                    let args = iter.map(|s| s.to_string()).collect::<Vec<String>>();
                    (v.closure)(&mut self.shared_state, args);
                },
                None => {
                    if command_name == "" {
                        println!("");
                    } else {
                        println!("Ignoring unrecognised command {}. Use help to view available commands", command_name);
                    }
                },
            }
        }
    }
}
