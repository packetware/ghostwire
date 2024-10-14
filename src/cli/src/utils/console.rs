use colored::*;

/// Print a success message to the console.
pub fn print_success(message: &str) {
    println!(
        "{} {} {}",
        ">>>".bold().blue(),
        message.bold().green(),
        "<<<".bold().blue()
    );
}

/// Print a success message to the console.
pub fn print_error(message: &str) {
    println!(
        "{} {} {}",
        ">>>".bold().blue(),
        message.bold().red(),
        "<<<".bold().blue()
    );
}
