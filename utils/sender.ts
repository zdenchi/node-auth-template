import axios, { AxiosResponse, AxiosRequestConfig } from 'axios';

type SMSPayload = {
  to: string;
  text: string;
}

type EmailPayload = {
  to: string;
  subject: string;
  template: string;
  variables?: Record<string, string>;
}

export const sendSMS = async ({ to, text }: SMSPayload) => {
  const { SMS_TOKEN, SMS_SENDER } = process.env;
  const options = {
    method: 'POST',
    url: 'https://im.smsclub.mobi/sms/send',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${SMS_TOKEN}`
    },
    data: {
      phone: [to],
      message: text,
      src_addr: SMS_SENDER
    }
  }

  try {
    const response = await axios(options);
    return response.status;
  } catch (error) {
    console.log('[sender](sendSMS):', error);
  }
}

export const sendEmail = async ({ to, subject, template, variables }: EmailPayload) => {
  const { MX_DOMAIN, MG_API_KEY } = process.env;
  const options: AxiosRequestConfig = {
    method: 'POST',
    url: `https://api.eu.mailgun.net/v3/mg.${MX_DOMAIN}/messages`,
    headers: { 'Content-Type': 'application/json' },
    auth: { username: 'api', password: MG_API_KEY as string },
    data: {
      from: `noreply@${MX_DOMAIN}`,
      to,
      subject,
      template,
      'h:X-Mailgun-Variables': JSON.stringify(variables),
    }
  }

  try {
    const response: AxiosResponse = await axios(options);
    return response.status;
  } catch (error) {
    console.log('[sender](sendEmail):', error);
  }
};
