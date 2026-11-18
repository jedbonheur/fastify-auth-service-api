export interface Mailer {
  sendEmailVerification(to: string, verifyUrl: string): Promise<void>;
  sendPasswordReset(to: string, resetUrl: string): Promise<void>;
}

/** Dev / MVP adapter — logs links to the console (swap later for SMTP/Resend). */
export class ConsoleMailer implements Mailer {
  async sendEmailVerification(to: string, verifyUrl: string): Promise<void> {
    console.log(`[mail:console] Email verification for ${to}`);
    console.log(`[mail:console] Link: ${verifyUrl}`);
  }

  async sendPasswordReset(to: string, resetUrl: string): Promise<void> {
    console.log(`[mail:console] Password reset for ${to}`);
    console.log(`[mail:console] Link: ${resetUrl}`);
  }
}
