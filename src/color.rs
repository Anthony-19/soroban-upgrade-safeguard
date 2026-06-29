/// Return whether colored output should be disabled for this invocation.
///
/// The caller supplies the flag, environment, and terminal state so the
/// decision can be unit-tested without depending on the test process stdout.
pub fn should_disable_color(
    no_color_flag: bool,
    no_color_env_present: bool,
    stdout_is_terminal: bool,
) -> bool {
    no_color_flag || no_color_env_present || !stdout_is_terminal
}
