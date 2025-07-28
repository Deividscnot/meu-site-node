require('dotenv').config();
const twilio = require('twilio')(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

(async () => {
  try {
    console.log('📲 Teste: enviando SMS...');
    const msg = await twilio.messages.create({
      body: 'Teste de SMS via Twilio!',
      from: process.env.TWILIO_PHONE_NUMBER,
      to: process.env.ADMIN_PHONE_NUMBER
    });
    console.log('✅ Teste OK! SID:', msg.sid);
  } catch (err) {
    console.error('❌ Teste falhou:', err.code, err.message);
  }
})();
