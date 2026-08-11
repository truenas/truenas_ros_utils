// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Drive a real PAM service from a terminal, printing the sequence as it goes.
//!
//! ```sh
//! cargo run -p truenas_pam --example login -- truenas alice
//! ```
//!
//! The service defaults to `truenas` and the user is asked for by the stack if
//! it is not given. Anything a module asks for is put to the terminal, with
//! echo off for the prompts that want it off.
//!
//! This is for looking at a stack the suites cannot run: one that needs
//! privilege, a directory server, or a second factor. The suites in `tests/`
//! run their own service files and need neither.
//!
//! # Safety
//!
//! Turning terminal echo off is a `termios` call, so this example lifts the
//! workspace's `deny(unsafe_code)`. The library needs none.
#![allow(unsafe_code)]

use std::error::Error;
use std::io::{self, IsTerminal, Write};
use std::time::Duration;
use truenas_pam::{Authenticator, MsgStyle, Secret, Stage, Step, Transaction};

/// Terminal echo, off until this is dropped.
struct EchoOff(libc::termios);

impl EchoOff {
    fn new() -> io::Result<EchoOff> {
        // SAFETY: an out-parameter for the current settings of stdin.
        let mut term = unsafe {
            let mut term = std::mem::zeroed::<libc::termios>();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut term) != 0 {
                return Err(io::Error::last_os_error());
            }
            term
        };
        let saved = term;
        term.c_lflag &= !libc::ECHO;
        // SAFETY: settings read from this same terminal, with one flag
        // cleared.
        if unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term)
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(EchoOff(saved))
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: the settings this terminal had before, restored once.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.0)
        };
    }
}

/// Put one message to the terminal, and read an answer if it wanted one.
fn ask(style: MsgStyle, text: &str) -> io::Result<Option<Secret>> {
    if !style.wants_response() {
        println!("[{style:?}] {text}");
        return Ok(None);
    }
    print!("{text}");
    io::stdout().flush()?;

    // Nothing to suppress when the input is not a terminal, and `tcgetattr`
    // on a pipe only fails.
    let hidden = match style {
        MsgStyle::PromptEchoOff if io::stdin().is_terminal() => {
            Some(EchoOff::new()?)
        }
        _ => None,
    };
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if hidden.is_some() {
        println!();
    }
    Ok(Some(Secret::from(line.trim_end_matches('\n'))))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let service = args.next().unwrap_or_else(|| "truenas".to_owned());

    let mut builder = Transaction::builder(&service).rhost("localhost");
    if let Some(user) = args.next() {
        builder = builder.user(&user);
    }
    let mut login =
        Authenticator::new(builder.build()?).timeout(Duration::from_secs(60));

    let mut step = login.begin();
    loop {
        match step {
            Ok(Step::Prompt(ref messages)) => {
                let mut answers = Vec::with_capacity(messages.len());
                for message in messages {
                    answers.push(ask(message.style(), &message.text())?);
                }
                step = login.respond(answers);
            }
            Ok(Step::Done) => break,
            Err(e) => {
                println!("{:?}: {e}", login.stage());
                return Ok(());
            }
        }
    }
    println!("{:?}", login.stage());

    if let Err(e) = login.acct_mgmt() {
        println!("account: {e}");
        return Ok(());
    }
    println!("account: ok");

    match login.login() {
        Ok(()) => println!("{:?}", login.stage()),
        Err(e) => {
            println!("session: {e}");
            return Ok(());
        }
    }

    // Whatever the stack established is readable here, which is where a
    // consumer picks up what a module left for it.
    let txn = login.transaction()?;
    println!("user: {:?}", txn.user()?);
    for (name, value) in txn.env()? {
        println!("env: {name}={value}");
    }
    for round in txn.messages() {
        for message in round {
            println!("said: [{:?}] {}", message.style(), message.text());
        }
    }

    login.logout()?;
    assert_eq!(login.stage(), Stage::Ended);
    println!("{:?}", login.stage());
    Ok(())
}
