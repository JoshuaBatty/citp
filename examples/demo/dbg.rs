

/// Macro to print text in red.
macro_rules! println_red {
    ($($arg:tt)*) => ({
        println!("{}",
            ansi_term::Color::Red.paint(format!($($arg)*))
        );
    });
}

macro_rules! println_green {
    ($($arg:tt)*) => ({
        println!("{}",
            ansi_term::Color::Green.paint(format!($($arg)*))
        );
    });
}

macro_rules! println_yellow {
    ($($arg:tt)*) => ({
        println!("{}",
            ansi_term::Color::Yellow.paint(format!($($arg)*))
        );
    });
}

macro_rules! println_blue {
    ($($arg:tt)*) => ({
        println!("{}",
            ansi_term::Color::Blue.paint(format!($($arg)*))
        );
    });
}