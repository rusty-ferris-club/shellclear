use insta::assert_debug_snapshot;
use serde_derive::Deserialize;
use shellclear::data::SensitiveCommands;
use shellclear::engine::SENSITIVE_COMMANDS;

#[derive(Debug, Deserialize, Clone)]
struct TestSensitivePatterns {
    pub name: String,
    pub test: String,
    pub expected: String,
}

#[allow(dead_code)]
#[derive(Debug)]
struct TestPatternResult {
    name: String,
    test: String,
    detect: String,
    expected: String,
}

#[test]
fn can_detect_regex_sensitive_patterns() {
    let patterns: Vec<SensitiveCommands> = serde_yaml::from_str(SENSITIVE_COMMANDS).unwrap();

    for pattern in &patterns {
        let pattern_id = pattern.id.to_lowercase().replace(" ", "_");
        let pattern_file = format!("tests/suites_sensitive_patterns/{}.yaml", pattern_id);
        let f = match std::fs::File::open(pattern_file) {
            Ok(f) => f,
            Err(_e) => {
                println!("not found tests for {}", pattern.id);
                return assert!(false);
            }
        };
        let tests: Vec<TestSensitivePatterns> = serde_yaml::from_reader(f).unwrap();
        let mut results = Vec::new();
        for test in tests {
            let caps = pattern.test.captures(&test.test).unwrap();
            results.push(TestPatternResult {
                name: test.name,
                test: test.test.clone(),
                detect: caps
                    .get(pattern.secret_group as usize)
                    .map_or("", |m| m.as_str())
                    .to_string(),
                expected: test.expected,
            })
        }
        assert_debug_snapshot!(pattern_id, results);
    }
}
