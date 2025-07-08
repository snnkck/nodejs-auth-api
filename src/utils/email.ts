import nodemailer from 'nodemailer';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

// Gmail transporter
const gmailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASSWORD // Google hesabınızdan App Password oluşturun
  }
});

export const sendEmail = async (options: EmailOptions): Promise<void> => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@yourapp.com',
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text
    };

    const info = await gmailTransporter.sendMail(mailOptions);
    console.log('Email sent successfully:', info.messageId);
  } catch (error) {
    console.error('Email sending error:', error);
    throw new Error('Failed to send email');
  }
};

// Test email gönderimi için
export const sendTestEmail = async (): Promise<void> => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'test@yourapp.com',
      to: 'test@example.com',
      subject: 'Test Mail',
      text: 'Bu bir test mailidir.',
      html: '<h1>Merhaba!</h1><p>Bu bir test mailidir.</p>'
    };

    const info = await gmailTransporter.sendMail(mailOptions);
    console.log('Test email sent:', info.messageId);
  } catch (error) {
    console.error('Test email error:', error);
  }
};

export default sendEmail;