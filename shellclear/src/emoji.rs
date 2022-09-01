use std::env;

pub struct Emojis {
    pub alarm: String,
    pub confetti: String,
}

impl Default for Emojis {
    fn default() -> Self {
        if env::consts::OS == "windows" {
            Self {
                alarm: "".to_string(),
                confetti: "".to_string(),
            }
        } else {
            Self {
                alarm: "🚨".to_string(),
                confetti: "🎉".to_string(),
            }
        }
    }
}
