use crate::{C, S};

use super::Emailer;
use ulid::Ulid;

#[derive(Debug, Clone)]
pub struct CustomEmail {
    title: String,
    line_one: String,
    line_two: Option<String>,
    button: Option<EmailButton>,
}

impl CustomEmail {
    pub fn new(
        title: String,
        line_one: String,
        line_two: Option<String>,
        hyper_link: Option<String>,
        button_text: Option<String>,
    ) -> Self {
        let button = if let (Some(link), Some(text)) = (hyper_link, button_text) {
            Some(EmailButton { link, text })
        } else {
            None
        };

        Self {
            title,
            line_one,
            line_two,
            button,
        }
    }
}

#[derive(Debug, Clone)]
pub enum EmailTemplate {
    /// secret, will handle to secret-to-link in enum
    Verify(Ulid),
    AccountLocked,
    PasswordChanged,
    DownloadData,
    /// secret, will handle to secret-to-link in enum
    PasswordResetRequested(Ulid),
    TwoFAEnabled,
    TwoFADisabled,
    TwoFABackupEnabled,
    TwoFABackupReGenerated,
    TwoFABackupDisabled,
    Custom(CustomEmail),
}

impl EmailTemplate {
    pub fn get_fallback(&self) -> String {
        format!(
            "{},\n{}\n{}\n",
            self.get_subject(),
            self.get_line_one(),
            self.get_line_two().unwrap_or_default()
        )
    }

    pub fn get_subject(&self) -> String {
        match self {
            Self::DownloadData => S!("Download Data"),
            Self::AccountLocked => S!("Security Alert"),
            Self::Custom(custom_email) => C!(custom_email.title),
            Self::PasswordChanged => S!("Password Changed"),
            Self::PasswordResetRequested(_) => S!("Password Reset Requested"),
            Self::TwoFABackupDisabled => S!("Two-Factor Backup Disabled"),
            Self::TwoFABackupEnabled => S!("Two-Factor Backup Enabled"),
            Self::TwoFABackupReGenerated => S!("Two-Factor Backups re-generated"),
            Self::TwoFADisabled => S!("Two-Factor Disabled"),
            Self::TwoFAEnabled => S!("Two-Factor Enabled"),
            Self::Verify(_) => S!("Verify Email Address"),
        }
    }

    pub fn get_button(&self) -> Option<EmailButton> {
        match self {
            Self::PasswordResetRequested(link) => Some(EmailButton {
                link: format!("/user/reset/{link}"),
                text: S!("RESET PASSWORD 🔒"),
            }),
            Self::Verify(link) => Some(EmailButton {
                link: format!("/user/verify/{link}"),
                text: S!("VERIFY EMAIL ADDRESS 📧"),
            }),
            Self::TwoFAEnabled => Some(EmailButton {
                link: S!("/user/settings/"),
                text: S!("GENERATE BACKUP CODES ⭐"),
            }),
            Self::Custom(custom_email) => custom_email.button.as_ref().map(|button| EmailButton {
                link: C!(button.link),
                text: C!(button.text),
            }),
            _ => None,
        }
    }

    pub fn get_line_one(&self) -> String {
        match self {
            Self::Custom(custom_email) => C!(custom_email.line_one),
            Self::DownloadData => S!("You have requested a copy of your user data"),
            Self::AccountLocked => S!("Due to multiple failed login attempts your account has been locked."),
            Self::PasswordChanged => S!("The password for your staticPi account has been changed."),
            Self::PasswordResetRequested(_) => S!("This password reset link will only be valid for one hour"),
            Self::TwoFABackupDisabled => S!("You have removed the Two-Factor Authentication backup codes for your staticPi account. New backup codes can be created at any time from the user settings page."),
            Self::TwoFABackupEnabled => S!("You have created Two-Factor Authentication backup codes for your staticPi account. The codes should be stored somewhere secure"),
            Self::TwoFABackupReGenerated => S!("You have re-generated Two-Factor Authentication backup codes for your staticPi account. Your previous backup codes are now invalid. The new codes should be stored somewhere secure."),
            Self::TwoFADisabled => S!("You have disabled Two-Factor Authentication for your staticPi account."),
            Self::TwoFAEnabled => S!("You have enabled Two-Factor Authentication for your staticPi account, it is recommended to create and save backup codes, these can be generated in the user settings area."),
            Self::Verify(_) => S!("Welcome to staticPi, before you start we just need you to verify this email address."),
        }
    }

    pub fn get_line_two(&self) -> Option<String> {
        let contact_support =
            S!("If you did not enable this setting, please contact support as soon as possible.");
        match self {
            Self::AccountLocked => {
                Some(S!("Please contact support in order to unlock your account"))
            }
            Self::PasswordChanged
            | Self::TwoFAEnabled
            | Self::TwoFADisabled
            | Self::TwoFABackupReGenerated
            | Self::TwoFABackupDisabled
            | Self::DownloadData
            | Self::TwoFABackupEnabled => Some(contact_support),
            Self::PasswordResetRequested(_) => Some(S!(
                "If you did not request a password reset then please ignore this email"
            )),
            Self::Custom(custom_email) => C!(custom_email.line_two),
            Self::Verify(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailButton {
    link: String,
    text: String,
}

fn create_template(input: &Emailer, domain: &str) -> String {
    let full_domain = format!("https://www.{domain}");
    let mut template = format!(
        r"<mjml>
    <mj-head>
        <mj-title>
            {title}
        </mj-title>
        <mj-preview>{title}</mj-preview>
        <mj-attributes>
            <mj-all font-family='Open Sans, Tahoma, Arial, sans-serif'></mj-all>
        </mj-attributes>
    </mj-head>
    
    <mj-body background-color='#f5f4f2' width='750px'>
        <mj-section padding-top='30px'></mj-section>
        <mj-section background-color='#c31c4a' padding-bottom='15px' padding-top='15px' text-align='center'>
            <mj-column width='100%'>
                <mj-image src='{full_domain}/img/emailer_header.png' href='{full_domain}' alt='staticPi.com logo' align='left' border='none' width='175px' padding-left='20px' padding-right='0px' padding-bottom='0px' padding-top='0'></mj-image>
            </mj-column>
        </mj-section>

        <mj-section background-color='#fafafa' padding-bottom='20px' padding-top='20px'>
            <mj-column vertical-align='middle' width='100%'>
                
                <mj-text line-height='1.2' align='left' color='#000000' font-size='18px' padding-left='25px' padding-right='25px'>
                    Hi {name},
                 </mj-text>
                <mj-text line-height='1.2' align='left' color='#000000' font-size='18px' padding-left='25px' padding-right='25px'>
                    {line_one}
                </mj-text>",
        title = input.template.get_subject(),
        name = input.name,
        line_one = input.template.get_line_one()
    );

    if let Some(line_two) = input.template.get_line_two() {
        let line_two_section = format!(
            r"<mj-text line-height='1.2' align='left' color='#000000' font-size='18px' padding-left='25px' padding-right='25px'>
                {line_two}
            </mj-text>"
        );
        template.push_str(&line_two_section);
    }
    if let Some(mut button) = input.template.get_button() {
        // This is dirty, need to come up with a better solution
        if !button.link.starts_with("http") {
            button.link = format!("{full_domain}{}", button.link);
        }

        let button_section = format!(
            r"<mj-button href='{link}' align='center' font-size='20px' font-weight='bold' background-color='#329C74' padding-top='25px' padding-bottom='25px' border-radius='30px' color='#ffffff' >
                {text}
            </mj-button>
            <mj-text line-height='1.2' align='left' color='#000000' font-size='12px' padding-left='25px' padding-right='25px'>
                    or copy and paste this address into the browser address bar
                    </mj-text>
            <mj-text line-height='1.2' align='left' color='#000000' font-size='10px' padding-left='25px' padding-right='25px'>
                <a style='word-break: break-all' href='{link}'>
                    {link}
                </a>
            </mj-text>",
            link = button.link,
            text = button.text
        );
        template.push_str(&button_section);
    }
    let end_section = format!(
        r"<mj-divider border-color='#c31c4a' padding-top='20px' padding-bottom='20px' border-width='2px' />
        <mj-text line-height='1.2' align='center' color='#000000' font-size='15px' padding-left='25px' padding-right='25px'>
        <a href='{full_domain}'>
            {full_domain}
        </a> © 2020-
        </mj-text>
         <mj-text line-height='1.2' align='center' color='#000000' font-size='12px' padding-left='25px' padding-right='25px' padding-top='15px'>
            responses sent to this email address are not read
         </mj-text>
        </mj-column>
        </mj-section>
        <mj-section padding-bottom='30px'>
    </mj-section>
</mj-body>
</mjml>"
    );
    template.push_str(&end_section);
    template
}

/// Use a `EmailTemplate` to create a parsed mjml html string
/// Is parsed on own thread
#[expect(clippy::cognitive_complexity)]
pub fn create_html_string(input: &Emailer) -> Option<String> {
    let template = create_template(input, input.env.get_domain());

    match mrml::parse(template) {
        Ok(root) => {
            let opts = mrml::prelude::render::RenderOptions::default();
            match root.render(&opts) {
                Ok(email_string) => Some(email_string),
                Err(e) => {
                    tracing::error!("{e:?}");
                    tracing::error!("email render error");
                    None
                }
            }
        }
        Err(e) => {
            tracing::error!("{e:?}");
            tracing::error!("mrml parsing error");
            None
        }
    }
}

/// cargo watch -q -c -w src/ -x 'test emailer_template -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::pedantic, clippy::nursery)]
mod tests {

    use crate::{emailer::EmailerEnv, parse_env};

    use super::*;

    #[test]
    fn emailer_template_create_template() {
        let app_env = parse_env::AppEnv::get_env();
        let emailer = EmailerEnv::new(&app_env);

        // let secret = "test_secret";
        let secret = Ulid::new();

        let create_input = |template: EmailTemplate| {
            Emailer::new("john smith", "email@example.com", template, &emailer)
        };

        let input = create_input(EmailTemplate::AccountLocked);
        let result = create_template(&input, &app_env.domain);
        //title
        assert!(result.contains("Security Alert"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(
            result.contains("Due to multiple failed login attempts your account has been locked.")
        );
        // no button
        assert!(!result.contains("<mj-button"));
        assert!(!result.contains("or copy and paste this address into the browser address bar"));

        let input = create_input(EmailTemplate::PasswordChanged);
        let result = create_template(&input, &app_env.domain);
        assert!(result.contains("Hi john smith,"));
        assert!(result.contains("The password for your staticPi account has been changed."));
        assert!(result.contains(
            "If you did not enable this setting, please contact support as soon as possible."
        ));
        assert!(!result.contains("<mj-button"));
        assert!(!result.contains("or copy and paste this address into the browser address bar"));

        let input = create_input(EmailTemplate::PasswordResetRequested(secret.to_owned()));
        let result = create_template(&input, &app_env.domain);
        // title
        assert!(result.contains("Password Reset Requested"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(result.contains("This password reset link will only be valid for one hour"));
        // line two
        assert!(result
            .contains("If you did not request a password reset then please ignore this email"));
        // button
        assert!(result.contains("<mj-button"));
        assert!(result.contains("or copy and paste this address into the browser address bar"));
        let link = format!(
            "<a style='word-break: break-all' href='https://www.{}/user/reset/{}'>",
            app_env.domain,
            secret.to_string()
        );

        assert!(result.contains(&link));
        assert!(result.contains("RESET PASSWORD"));

        let input = create_input(EmailTemplate::TwoFABackupEnabled);
        let result = create_template(&input, &app_env.domain);
        // title
        assert!(result.contains("Two-Factor Backup Enabled"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(result.contains("You have created Two-Factor Authentication backup codes for your staticPi account. The codes should be stored somewhere secure"));
        // button
        assert!(!result.contains("<mj-button"));
        assert!(!result.contains("or copy and paste this address into the browser address bar"));

        let input = create_input(EmailTemplate::TwoFABackupDisabled);
        let result = create_template(&input, &app_env.domain);
        // title
        assert!(result.contains("Two-Factor Backup Disabled"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(result.contains("You have removed the Two-Factor Authentication backup codes for your staticPi account. New backup codes can be created at any time from the user settings page."));
        // button
        assert!(!result.contains("<mj-button"));
        assert!(!result.contains("or copy and paste this address into the browser address bar"));

        let input = create_input(EmailTemplate::TwoFAEnabled);
        let result = create_template(&input, &app_env.domain);
        // title
        assert!(result.contains("Two-Factor Enabled"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(result.contains("You have enabled Two-Factor Authentication for your staticPi account, it is recommended to create and save backup codes, these can be generated in the user settings area."));
        // button
        assert!(result.contains(
            "If you did not enable this setting, please contact support as soon as possible."
        ));
        assert!(result.contains("<mj-button"));
        assert!(result.contains("or copy and paste this address into the browser address bar"));
        let link = format!(
            "<a style='word-break: break-all' href='https://www.{}/user/settings/'>",
            app_env.domain
        );
        assert!(result.contains(&link));
        assert!(result.contains("GENERATE BACKUP CODES"));

        let input = create_input(EmailTemplate::TwoFADisabled);
        let result = create_template(&input, &app_env.domain);
        // title
        assert!(result.contains("Two-Factor Disabled"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(result
            .contains("You have disabled Two-Factor Authentication for your staticPi account"));
        // button
        assert!(result.contains(
            "If you did not enable this setting, please contact support as soon as possible."
        ));
        assert!(!result.contains("<mj-button"));
        assert!(!result.contains("or copy and paste this address into the browser address bar"));

        let input = create_input(EmailTemplate::Verify(secret));
        let result = create_template(&input, &app_env.domain);
        // title
        assert!(result.contains("Verify Email Address"));
        // name
        assert!(result.contains("Hi john smith,"));
        // line one
        assert!(result.contains(
            "Welcome to staticPi, before you start we just need you to verify this email address."
        ));
        // button
        assert!(result.contains("<mj-button"));
        assert!(result.contains("or copy and paste this address into the browser address bar"));
        let link = format!(
            "<a style='word-break: break-all' href='https://www.{}/user/verify/{}'>",
            app_env.domain, secret
        );
        assert!(result.contains(&link));
        assert!(result.contains("VERIFY EMAIL ADDRESS"));
    }

    #[test]
    fn emailer_template() {
        let app_env = parse_env::AppEnv::get_env();
        let emailer = &EmailerEnv::new(&app_env);

        let secret = Ulid::new();

        let input = Emailer::new(
            "john smith",
            "email@example.com",
            EmailTemplate::PasswordResetRequested(secret),
            emailer,
        );
        let result = create_html_string(&input);
        assert!(result.is_some());

        let result = result.unwrap_or_default();

        assert!(result.starts_with("<!doctype html><html xmlns=\"http://www.w3.org/1999/xhtml\""));
        let link = format!(
            "href=\"https://www.{}/user/reset/{}\"",
            app_env.domain, secret
        );
        assert!(result.contains(&link));
    }
}
