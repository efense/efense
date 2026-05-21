// SPDX-License-Identifier: Apache-2.0

mod apply;
mod monitor;
mod pin;
mod purge;
mod show;

use efense::EfenseError;

use self::{
    apply::CommandApply, monitor::CommandMonitor, purge::CommandPurge,
    show::CommandShow,
};

#[tokio::main]
async fn main() -> Result<(), EfenseError> {
    let mut cli_cmd = clap::Command::new("efctl")
        .about("efense CLI")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand(CommandApply::new_cmd())
        .subcommand(CommandMonitor::new_cmd())
        .subcommand(CommandPurge::new_cmd())
        .subcommand(CommandShow::new_cmd());
    let matches = cli_cmd.get_matches_mut();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    if let Some(matches) = matches.subcommand_matches(CommandApply::CMD) {
        CommandApply::handle(matches).await
    } else if let Some(matches) =
        matches.subcommand_matches(CommandMonitor::CMD)
    {
        CommandMonitor::handle(matches).await
    } else if let Some(matches) = matches.subcommand_matches(CommandPurge::CMD)
    {
        CommandPurge::handle(matches).await
    } else if let Some(matches) = matches.subcommand_matches(CommandShow::CMD) {
        CommandShow::handle(matches).await
    } else {
        Ok(())
    }
}
