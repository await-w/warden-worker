mod telegram;
mod r#trait;
mod wework;

pub use telegram::TelegramChannel;
pub use r#trait::{Channel, ChannelError};
pub use wework::WeWorkChannel;

use crate::notify::types::{ChannelType, Notification};

pub async fn dispatch_to_channels(
    notification: &Notification,
    env: &worker::Env,
) -> Result<(), ChannelError> {
    let mut errors = Vec::new();

    if let Some(channel) = WeWorkChannel::from_env(env) {
        if channel.channel_type() == ChannelType::WeWork {
            if let Err(e) = channel.send(notification).await {
                errors.push(format!("WeWork: {}", e.message));
            }
        }
    }

    if let Some(channel) = TelegramChannel::from_env(env) {
        if channel.channel_type() == ChannelType::Telegram {
            if let Err(e) = channel.send(notification).await {
                errors.push(format!("Telegram: {}", e.message));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ChannelError {
            message: errors.join("; "),
        })
    }
}
