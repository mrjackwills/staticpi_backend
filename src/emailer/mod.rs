#![allow(unused)]
mod template;

use crate::{
    api_error::ApiError,
    database::{email_log::ModelEmailLog, ip_user_agent::ModelUserAgentIp},
    parse_env::{AppEnv, RunMode},
};

use lettre::{
    address::AddressError,
    message::{header, Mailbox, MultiPart, SinglePart},
    transport::smtp::{authentication::Credentials, AsyncSmtpTransportBuilder},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use sqlx::PgPool;
use tracing::{error, info, trace};

use self::template::create_html_string;

pub use self::template::{CustomEmail, EmailTemplate};

/// Store secrets in here, and then use getters methods to get them
#[derive(Debug, Clone)]
pub struct EmailerEnv {
    domain: String,
    from_address: String,
    host: String,
    name: String,
    password: String,
    port: u16,
    run_mode: RunMode,
}

impl EmailerEnv {
    pub fn new(app_env: &AppEnv) -> Self {
        Self {
            domain: app_env.domain.clone(),
            from_address: app_env.email_from_address.clone(),
            host: app_env.email_host.clone(),
            name: app_env.email_name.clone(),
            password: app_env.email_password.clone(),
            port: app_env.email_port,
            run_mode: app_env.run_mode,
        }
    }
    fn get_from_mailbox(&self) -> Result<Mailbox, AddressError> {
        format!("{} <{}>", self.name, self.from_address).parse::<Mailbox>()
    }

    fn get_credentials(&self) -> Credentials {
        Credentials::new(self.from_address.clone(), self.password.clone())
    }

    fn get_mailer(&self) -> Result<AsyncSmtpTransportBuilder, lettre::transport::smtp::Error> {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host)
    }

    const fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_domain(&self) -> &str {
        self.domain.as_str()
    }

    pub const fn get_production(&self) -> bool {
        self.run_mode.is_production()
    }
}

#[derive(Debug, Clone)]
pub struct Emailer {
    name: String,
    email_address: String,
    template: EmailTemplate,
    emailer: EmailerEnv,
}

impl Emailer {
    pub fn new(
        name: &str,
        email_address: &str,
        template: EmailTemplate,
        email_env: &EmailerEnv,
    ) -> Self {
        Self {
            name: name.to_owned(),
            email_address: email_address.to_owned(),
            template,
            emailer: email_env.clone(),
        }
    }

    /// Insert email log, then send email on it's own thread, as not to slow down any api responses
    /// And assume that it succeeds, and inform the user that it was succeeded
    pub async fn send(
        &self,
        postgres: &PgPool,
        useragent_ip: &ModelUserAgentIp,
    ) -> Result<(), ApiError> {
        if ModelEmailLog::get_count_hour(postgres).await?.count < 275 {
            let email_log =
                ModelEmailLog::insert(postgres, &self.template, useragent_ip, &self.email_address)
                    .await?;
            let postgres = postgres.clone();
            tokio::spawn(Self::_send(self.clone(), postgres, email_log));
        } else {
            error!("email limit hit");
        }
        Ok(())
    }

    // Handle all errors in this function, just trace on any issues
    #[cfg(test)]
    async fn _send(emailer: Self, postgres: PgPool, email_log: ModelEmailLog) {
        let to_box = format!("{} <{}>", emailer.name, emailer.email_address).parse::<Mailbox>();
        if let (Ok(from), Ok(to)) = (emailer.emailer.get_from_mailbox(), to_box) {
            let subject = emailer.template.get_subject();
            if let Some(html_string) = create_html_string(&emailer) {
                let message_builder = Message::builder()
                    .from(from)
                    .to(to)
                    .subject(subject)
                    .multipart(
                        MultiPart::alternative() // This is composed of two parts.
                            .singlepart(
                                SinglePart::builder()
                                    .header(header::ContentType::TEXT_PLAIN)
                                    .body(emailer.template.get_fallback()),
                            )
                            .singlepart(
                                SinglePart::builder()
                                    .header(header::ContentType::TEXT_HTML)
                                    .body(html_string.clone()),
                            ),
                    );

                if let Ok(message) = message_builder {
                    std::fs::write("/dev/shm/email_headers.txt", message.headers().to_string())
                        .ok();
                    std::fs::write("/dev/shm/email_body.txt", html_string).ok();
                    info!("Would be sending email if on production");
                } else {
                    email_log.update_sent_false(&postgres).await;
                    error!("unable to build message with Message::builder");
                }
            }
        } else {
            email_log.update_sent_false(&postgres).await;
            error!("unable to parse from_box or to_box");
        }
    }

    /// Handle all errors in this function, just error!(e) on any issues
    #[cfg(not(test))]
    async fn _send(emailer: Self, postgres: PgPool, email_log: ModelEmailLog) {
        let to_box = format!("{} <{}>", emailer.name, emailer.email_address).parse::<Mailbox>();
        if let (Ok(from), Ok(to)) = (emailer.emailer.get_from_mailbox(), to_box) {
            let subject = emailer.template.get_subject();
            if let Some(html_string) = create_html_string(&emailer) {
                let message_builder = Message::builder()
                    .from(from)
                    .to(to)
                    .subject(subject.clone())
                    .multipart(
                        MultiPart::alternative()
                            .singlepart(
                                SinglePart::builder()
                                    .header(header::ContentType::TEXT_PLAIN)
                                    .body(emailer.template.get_fallback()),
                            )
                            .singlepart(
                                SinglePart::builder()
                                    .header(header::ContentType::TEXT_HTML)
                                    .body(html_string.clone()),
                            ),
                    );

                if let Ok(message) = message_builder {
                    // Only send emails on production
                    if emailer.emailer.get_production() {
                        let creds = emailer.emailer.get_credentials();
                        match emailer.emailer.get_mailer() {
                            Ok(sender) => {
                                let transport = sender
                                    .credentials(creds)
                                    .port(emailer.emailer.get_port())
                                    .build();
                                match transport.send(message).await {
                                    Ok(_) => {
                                        trace!("Email sent successfully!");
                                    }
                                    Err(e) => {
                                        email_log.update_sent_false(&postgres).await;
                                        error!("{e:?}");
                                        error!("mailer.send error");
                                    }
                                }
                            }
                            Err(e) => {
                                email_log.update_sent_false(&postgres).await;
                                error!("{e:?}");
                                info!("Mailer relay error");
                            }
                        }
                    } else {
                        std::fs::write("/dev/shm/email_headers.txt", message.headers().to_string())
                            .ok();
                        std::fs::write("/dev/shm/email_body.txt", html_string).ok();
                        info!("Would be sending email if on production");
                    }
                } else {
                    email_log.update_sent_false(&postgres).await;
                    error!("unable to build message with Message::builder");
                }
            }
        } else {
            error!("unable to parse from_box or to_box");
            email_log.update_sent_false(&postgres).await;
        }
    }
}

/// cargo watch -q -c -w src/ -x 'test emailer_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {

    use super::*;
    use crate::{
        parse_env,
        servers::test_setup::{setup, TestSetup, TEST_EMAIL},
        sleep,
    };

    // Make sure emailer sends correctly, just save onto disk and check against that, rather than sending actual email!
    #[tokio::test]
    async fn emailer_mod_send_to_disk() {
        let app_env = parse_env::AppEnv::get_env();
        let emailer = EmailerEnv::new(&app_env);
        let test_setup = setup().await;
        // test_setup.

        let req = ModelUserAgentIp::get(
            &test_setup.postgres,
            &test_setup.redis,
            &TestSetup::gen_req(),
        )
        .await
        .unwrap();

        let email = Emailer::new(
            "john smith",
            "email@example.com",
            EmailTemplate::PasswordChanged,
            &emailer,
        );
        email.send(&test_setup.postgres, &req).await;

        // Need to sleep, as the email.send() function spawns onto it's own thread, 1ms should be enough to do everything it needs to
        sleep!(1);

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );

        let result = std::fs::read_to_string("/dev/shm/email_body.txt").unwrap();
        assert!(result.starts_with("<!doctype html><html xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:v=\"urn:schemas-microsoft-com:vml\" xmlns:o=\"urn:schemas-microsoft-com:office:office\"><head><title>"));
        assert!(result.contains("john smith"));

        let result = std::fs::read_to_string("/dev/shm/email_headers.txt").unwrap();
        assert!(result.contains("From: staticPi <noreply@staticpi.com>"));
        assert!(result.contains("To: \"john smith\" <email@example.com>"));
        assert!(result.contains("Subject: Password Changed"));

        std::fs::remove_file("/dev/shm/email_headers.txt").unwrap();
        std::fs::remove_file("/dev/shm/email_body.txt").unwrap();
    }

    /// Emails not send if more than 275 have been sent in the previous hour
    #[tokio::test]
    async fn emailer_mod_limit_exceeded() {
        let app_env = parse_env::AppEnv::get_env();
        let emailer = EmailerEnv::new(&app_env);
        let test_setup = setup().await;

        let req = ModelUserAgentIp::get(
            &test_setup.postgres,
            &test_setup.redis,
            &TestSetup::gen_req(),
        )
        .await
        .unwrap();
        let email = Emailer::new(
            "john smith",
            TEST_EMAIL,
            EmailTemplate::PasswordChanged,
            &emailer,
        );

        for i in 1..=275 {
            ModelEmailLog::insert(&test_setup.postgres, &email.template, &req, TEST_EMAIL)
                .await
                .unwrap();
        }

        let pre_count = ModelEmailLog::get_count_hour(&test_setup.postgres)
            .await
            .unwrap();
        TestSetup::delete_emails();

        email.send(&test_setup.postgres, &req).await;

        let post_count = ModelEmailLog::get_count_hour(&test_setup.postgres)
            .await
            .unwrap();

        assert_eq!(pre_count.count, post_count.count);
        assert!(std::fs::read_to_string("/dev/shm/email_headers.txt").is_err());
        assert!(std::fs::read_to_string("/dev/shm/email_body.txt").is_err());
    }
}
