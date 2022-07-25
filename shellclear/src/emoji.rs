pub struct Emojis {
    pub alarm: String,
    pub confetti: String,
}

impl Default for Emojis {
    fn default() -> Self {
        Self {
            alarm: "🚨".to_string(),
            confetti: "🎉".to_string(),
        }
    }
}
