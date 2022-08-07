use anyhow::anyhow;
use anyhow::Result;
use requestty::Question;

/// prompt select option
///
/// # Errors
///
/// Will return `Err` when interact error
pub fn select(message: &str, items: &Vec<String>) -> Result<usize> {
    let questions = Question::select("select")
        .message(message)
        .choices(items)
        .build();

    let answer = requestty::prompt_one(questions)?;
    match answer.as_list_item() {
        Some(a) => Ok(a.index),
        _ => Err(anyhow!("select option is empty")),
    }
}

/// prompt confirm message
///
/// # Errors
///
/// Will return `Err` when interact error
pub fn confirm(message: &str) -> Result<()> {
    let questions = Question::confirm("confirm").message(message).build();
    let answer = requestty::prompt_one(questions)?;
    match answer.as_bool() {
        Some(is_confirm) => {
            if !is_confirm {
                return Err(anyhow!("not confirmed"));
            }
        }
        _ => return Err(anyhow!("config option is empty")),
    }
    Ok(())
}
