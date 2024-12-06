const express = require('express');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const { Pool } = require('pg');
const axios = require('axios');
const { compareSync, hash } = require('bcryptjs');
require('dotenv').config();
const API_KEY_CODE = process.env.API_KEY_CODE;
const SECRET_KEY = process.env.SECRET_KEY;
const PREFIX = process.env.PREFIX;
const captchaSecretKey = process.env.CAPTCHA_SECRET_KEY_TEST;
const profileRouter = require('./routes/profile');
const config = require('./config.json');

const pool = new Pool(config.db);

const app = express();
app.use(express.json());
app.use('/profile', profileRouter);

const validateApiKey = async (req, res, next) => {
  const apiKey = req.header('x-api-key');

  const sourceApiKeys = await pool.query('SELECT "Id" FROM "' + PREFIX + 'POAPIKeys" WHERE "Code" = $1', [API_KEY_CODE])
  const sourceApiKey = sourceApiKeys.rows[0].Id;

  if (sourceApiKey || apiKey && apiKey === sourceApiKey) {
    next();
  } else {
    console.log({ message: 'Yetkisiz erişim: API anahtarı hatalı.' });
    return res.status(401).json({ message: 'Yetkisiz erişim: API anahtarı hatalı.' });
  }
};

const authMiddleware = (req, res, next) => {
  const token = req.headers['x-access-token'];  // Token'i istek başlığından al

  if (!token) {
    console.log({ message: 'Session token gönderilmedi.' });
    return res.status(403).json({ message: 'Session token gönderilmedi.' });
  }

  // Token'i doğrula
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.log({ message: 'Session token doğrulanamadı.' });
      return res.status(401).json({ message: 'Session token doğrulanamadı.' });
    }

    // Token geçerli ise decoded verisini req.user'a ekleyerek sonraki aşamaya geç
    req.user = decoded;
    next();
  });
};

app.use((req, res, next) => {

  // "/submit" rotası için middleware'i atla
  if (req.path === "/submit-captcha") return next();
  validateApiKey(req, res, next);
});

// Register endpoint
app.post('/register', async (req, res) => {
  const { identityNumber, name, surname, birthDate, email, phoneNumber, password, confirmPassword, recaptchaToken } = req.body;

  try {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const nameSurnameRegex = /^[a-zA-ZçÇğĞıİöÖşŞüÜ]+( [a-zA-ZçÇğĞıİöÖşŞüÜ]+)*$/;
    const birthDateRegex = /^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-(19|20)\d\d$/;
    const phoneNumberRegex = /^\+90 \d{3} \d{3} \d{2} \d{2}$/;
    const passwordRegex = /^(?=.*[a-zçğıöşü])(?=.*[A-ZÇĞİÖŞÜ])(?=.*[@$!%*?&.,;:])[A-Za-zçÇğĞıİöÖşŞüÜ\d@$!%*?&.,;:]{8,}$/;


    // Regex kontrolleri
    if (!email || !emailRegex.test(email)) {
      console.log({ message: 'Geçerli bir e-posta adresi giriniz.' });
      return res.status(400).json({ message: 'Geçerli bir e-posta adresi giriniz.' });
    }
    if (!name || !nameSurnameRegex.test(name)) {
      console.log({ message: 'Adınızı geçerli formatta giriniz.' });
      return res.status(400).json({ message: 'Adınızı geçerli formatta giriniz.' });
    }
    if (!surname || !nameSurnameRegex.test(surname)) {
      console.log({ message: 'Soyadınızı geçerli formatta giriniz.' });
      return res.status(400).json({ message: 'Soyadınızı geçerli formatta giriniz.' });
    }
    if (!birthDate || !birthDateRegex.test(birthDate)) {
      console.log({ message: 'Doğum tarihinizi geçerli formatta giriniz.' });
      return res.status(400).json({ message: 'Doğum tarihinizi geçerli formatta giriniz.' });
    }
    if (!phoneNumber || !phoneNumberRegex.test(phoneNumber)) {
      console.log({ message: 'Telefon numaranızı geçerli formatta giriniz.' });
      return res.status(400).json({ message: 'Telefon numaranızı geçerli formatta giriniz.' });
    }
    if (!password || !passwordRegex.test(password)) {
      console.log({ message: 'Parolanızı geçerli formatta giriniz.' });
      return res.status(400).json({ message: 'Parolanızı geçerli formatta giriniz.' });
    }
    if (password != confirmPassword) {
      console.log({ message: 'Parolalar eşleşmiyor.' });
      return res.status(400).json({ message: 'Parolalar eşleşmiyor.' });
    }

    // CAPCTHA kontrolü
    try {
      const verifyCaptchaResponse = await verifyCaptcha(recaptchaToken);
      if (!verifyCaptchaResponse.data.success) {
        console.log({ code: 2, message: "reCAPTCHA doğrulaması başarısız." });
        return res.status(400).json({ code: 2, message: "reCAPTCHA doğrulaması başarısız." })
      }
    }
    catch (captchaError) {
      console.log({ code: 2, message: "reCAPTCHA doğrulaması sırasında bir hata oluştu." });
      return res.status(500).json({ code: 2, message: "reCAPTCHA doğrulaması sırasında bir hata oluştu." })
    }

    // E-posta kontrolü
    const emailCheck = await pool.query('SELECT * FROM "' + PREFIX + 'Customers" WHERE "EmailAddress" = $1', [email]);
    if (emailCheck.rows.length > 0) {
      console.log({ message: 'Bu mail adresi daha önce kaydedilmiş, lütfen giriş yapınız.' });
      return res.status(400).json({ message: 'Bu mail adresi daha önce kaydedilmiş, lütfen giriş yapınız.' });
    }

    //TCKN format kontrolü
    const tcknDogrula = tckn_dogrula(identityNumber);
    if (!identityNumber || !tcknDogrula) {
      console.log({ message: 'Geçerli bir kimlik numarası giriniz.' });
      return res.status(400).json({ message: 'Geçerli bir kimlik numarası giriniz.' });
    }

    // IdentityNumber kontrolü
    const identityCheck = await pool.query('SELECT * FROM "' + PREFIX + 'Customers" WHERE "IdentityNumber" = $1', [identityNumber]);
    if (identityCheck.rows.length > 0) {
      console.log({ message: 'Bu kimlik numarası daha önce kaydedilmiş, lütfen giriş yapınız.' });
      return res.status(400).json({ message: 'Bu kimlik numarası daha önce kaydedilmiş, lütfen giriş yapınız.' });
    }

    try {
      const initiateResponse = await initiateProcess(req.body);
      return res.status(201).json({ message: 'Kullanıcı başarılı şekilde kaydedildi.', email: email });
    }
    catch (initiateerror) {
      console.log({ message: 'Girdiğiniz bilgiler ile kimlik bilgileri doğrulanamadı. Lütfen bilgilerinizi kontrol ederek yeniden deneyiniz.' });
      return res.status(400).json({ message: 'Girdiğiniz bilgiler ile kimlik bilgileri doğrulanamadı. Lütfen bilgilerinizi kontrol ederek yeniden deneyiniz.' })
    }

  } catch (err) {
    console.log({ message: 'Kayıt gerçekleştirilemedi.', hata: err.message });
    return res.status(500).json({ message: 'Kayıt gerçekleştirilemedi.', hata: err.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password, recaptchaToken } = req.body;
  const customerIP = req.header('x-forwarded-for');
  //statu 1: sms ve email false, 2: sms email true:AML false, 99: üçü de true 
  try {
    const result = await pool.query(`SELECT 
      "Id", 
      "Name", 
      "Surname", 
      "EmailAddress",
      "PhoneNumber", 
      "HashedPassword", 
      "PhoneVerificationStatus",
      "EmailVerificationStatus",
      "AMLStatus" 
      FROM "` + PREFIX + `Customers" 
      WHERE "EmailAddress" = $1`, [email]);
    const user = result.rows[0];

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    var hashedPassword = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);

    try {
      const verifyCaptchaResponse = await verifyCaptcha(recaptchaToken);
      if (!verifyCaptchaResponse.data.success) {
        console.log({ code: 2, message: "reCAPTCHA doğrulaması başarısız." });
        return res.status(400).json({ code: 2, message: "reCAPTCHA doğrulaması başarısız." })
      }
    }
    catch (captchaError) {
      console.log({ code: 2, message: "reCAPTCHA doğrulaması sırasında bir hata oluştu.", error: captchaError.message });
      return res.status(500).json({ code: 2, message: "reCAPTCHA doğrulaması sırasında bir hata oluştu.", error: captchaError.message })
    }

    // Email regex'e uygun mu kontrolü
    if (!email || !emailRegex.test(email)) {
      console.log({ message: 'Geçerli bir e-posta adresi giriniz.' });
      return res.status(400).json({ message: 'Geçerli bir e-posta adresi giriniz.' });
    }

    if (!user) {
      console.log({ message: 'Email ya da şifre hatalı.' });
      return res.status(400).json({ message: 'Email ya da şifre hatalı.' });
    }

    if (user.HashedPassword != hashedPassword) {
      console.log({ message: 'Email ya da şifre hatalı.' });
      return res.status(400).json({ message: 'Email ya da şifre hatalı.' });
    }

    var status = 0;

    if (!user.PhoneVerificationStatus || !user.EmailVerificationStatus) { status = 1 }
    else if (user.PhoneVerificationStatus && user.EmailVerificationStatus && !user.AMLStatus) { status = 2 }
    else if (user.PhoneVerificationStatus && user.EmailVerificationStatus && user.AMLStatus) { status = 3 }

    if (status == 3) {
      //Initiate Emakin Login SMS Module
      try {
        const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/initiateByProcess', {
          apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
          logonId: "support@bt.guru",
          logonProvider: "Organization",
          process: "c45309be-a1f7-4ef9-bf81-c695772911cc",
          task: "4c5f231a-1f95-4282-b938-5b90e170c4fd",
          version: null,
          data: `<LoginManagement>
                <CustomerId>${user.Id}</CustomerId>
                <PhoneNumber>${user.PhoneNumber}</PhoneNumber>
                <CustomerIP>${customerIP}</CustomerIP>
              </LoginManagement>`,
          culture: null
        });

      } catch (error) {
        console.log({ message: "SMS gönderilemedi!", error: error.message });
        return res.status(500).json({ message: "SMS gönderilemedi!", error: error.message });
      }
    }

    const superUsers = ["lutfullah@bt.guru", "aybike@bt.guru", "berkan@bt.guru", "ozan@bt.guru", "tahak@bt.guru", "baris@bt.guru"];
    var expiresIn = 3600;
    if (superUsers.includes(email)) { expiresIn = 2592000 }

    const expireDuration = 180000;
    var maskedPhoneNumber = user.PhoneNumber.substring(0, 8) + "*** **" + user.PhoneNumber.substring(14, 17);

    const token = jwt.sign({ customerId: user.Id, email: user.EmailAddress, nameSurname: (user.Name + ' ' + user.Surname), verifyStatus: status }, SECRET_KEY, { expiresIn: expiresIn });

    return res.status(200).json({ auth: true, message: "Giriş başarılı.", status: status, sessionToken: token, codeExpireDate: expireDuration, maskedPhoneNumber: maskedPhoneNumber });
  } catch (err) {
    console.log({ message: "Giriş yapılamadı.", error: err.message });
    return res.status(500).json({ message: "Giriş yapılamadı.", error: err.message });
  }
});

//Login için SMS doğrulaması
app.post('/verify-login-otp', authMiddleware, async (req, res) => {
  const customerIP = req.header('x-forwarded-for');
  const { smsCode } = req.body;
  const customerId = req.user?.customerId;

  const resultSession = await pool.query(`SELECT
    "Id",
    "PhoneVerificationCode", 
    "CustomerIP"
    FROM "` + PREFIX + `CustomerSessionLogs" 
    WHERE "CustomerId" = $1
    ORDER BY "RequestDate" DESC
    LIMIT 1`, [customerId]);

  if (resultSession.rowCount == 0) {
    console.log({ message: "Hatalı kod girdiniz." });
    return res.status(400).json({ message: "Hatalı kod girdiniz." });
  }

  const lastLogId = resultSession.rows[0].Id;
  const lastLogCustomerIP = resultSession.rows[0].CustomerIP;
  const lastVerificationCode = resultSession.rows[0].PhoneVerificationCode;

  const result = await pool.query(`SELECT 
    "Id",
    "Name", 
    "Surname", 
    "EmailAddress",
    "PhoneNumber", 
    "HashedPassword", 
    "PhoneVerificationStatus",
    "EmailVerificationStatus",
    "AMLStatus" 
    FROM "` + PREFIX + `Customers" 
    WHERE "Id" = $1`, [customerId]);
  const user = result.rows[0];
  const email = user.EmailAddress;

  if (smsCode != lastVerificationCode) {
    console.log({ message: "Hatalı kod girdiniz!" });
    return res.status(400).json({ message: "Hatalı kod girdiniz!" });
  }

  if (customerIP != lastLogCustomerIP) {
    console.log({ message: "IP değişikliği tespit edildi!" });
    return res.status(400).json({ message: "IP değişikliği tespit edildi!" });
  }

  try {
    // Emakin Trigger
    const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/trigger', {
      apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
      logonId: "support@bt.guru",
      logonProvider: "Organization",
      eventName: "VerificationLoginSMS." + lastLogId,
      inputData: null,
      testMode: false,
      culture: null
    });

    const superUsers = ["lutfullah@bt.guru", "aybike@bt.guru", "berkan@bt.guru", "ozan@bt.guru", "tahak@bt.guru", "baris@bt.guru"];
    var expiresIn = 3600;
    if (superUsers.includes(email)) { expiresIn = 2592000 }

    const token = jwt.sign({ customerId: user.Id, email: user.EmailAddress, nameSurname: (user.Name + ' ' + user.Surname), verifyStatus: 99 }, SECRET_KEY, { expiresIn: expiresIn });

    return res.status(200).json({ auth: true, message: "Giriş başarılı.", status: 99, sessionToken: token });
  } catch (err) {
    console.log({ message: 'SMS doğrulaması başarısız!', error: err.message });
    return res.status(500).json({ message: 'SMS doğrulaması başarısız!', error: err.message });
  }

});

// Register için SMS kod gönderimi
app.post('/send-sms-code', authMiddleware, async (req, res) => {
  const customerId = req.user?.customerId;
  try {
    // Emakin Trigger
    const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/trigger', {
      apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
      logonId: "support@bt.guru",
      logonProvider: "Organization",
      eventName: "VerificationSMS." + customerId,
      inputData: null,
      testMode: false,
      culture: null
    });

    return res.status(200).json({ message: 'SMS doğrulama kodu gönderildi.' });
  } catch (err) {
    console.log({ message: 'SMS doğrulama kodu gönderilemedi!', error: err.message });
    return res.status(500).json({ message: 'SMS doğrulama kodu gönderilemedi!', error: err.message });
  }
});

// Register için Email kod gönderimi
app.post('/send-email-code', authMiddleware, async (req, res) => {
  const customerId = req.user?.customerId;
  try {
    // Emakin Trigger
    const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/trigger', {
      apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
      logonId: "support@bt.guru",
      logonProvider: "Organization",
      eventName: "VerificationEmail." + customerId,
      inputData: null,
      testMode: false,
      culture: null
    });

    return res.status(200).json({ message: 'Email doğrulama kodu gönderildi.' });
  } catch (err) {
    console.log({ message: 'Email doğrulama kodu gönderilemedi!', error: err.message });
    return res.status(500).json({ message: 'Email doğrulama kodu gönderilemedi!', error: err.message });
  }
});

// Register için 2 faktörlü doğrulama
app.post('/twofactorauth', async (req, res) => {
  const { customerId, smsCode, emailCode } = req.body;

  try {
    const result = await pool.query(`SELECT 
      "Id", 
      "Name",
      "Surname",
      "EmailAddress", 
      "HashedPassword", 
      "PhoneVerificationCode",
      "EmailVerificationCode",
      "PhoneVerificationStatus",
      "EmailVerificationStatus",
      "AMLStatus" 
      FROM "` + PREFIX + `Customers" 
      WHERE "Id" = $1`, [customerId]);
    const user = result.rows[0];

    var status = 0;

    if (smsCode != user.PhoneVerificationCode || emailCode != user.EmailVerificationCode) { status = 1 }
    else { status = 2 }

    var smsStatus = user.PhoneVerificationCode == smsCode ? "SMS doğrulaması başarılı." : "SMS doğrulaması başarısız.";
    var emailStatus = user.EmailVerificationCode == emailCode ? "Email doğrulaması başarılı." : "Email doğrulaması başarısız.";

    const expiresIn = 3600;
    const token = jwt.sign({ customerId: user.Id, email: user.EmailAddress, nameSurname: (user.Name + ' ' + user.Surname) }, SECRET_KEY, { expiresIn: expiresIn });

    if (status == 1) {
      console.log({ message: 'Hesap doğrulanamadı!' });
      return res.status(403).json({ message: 'Hesap doğrulanamadı!', status: status, smsVerification: smsStatus, emailVerification: emailStatus });
    }

    if (user.PhoneVerificationStatus && user.EmailVerificationStatus) {
      console.log({ message: 'Hesap daha önce doğrulanmış!' });
      return res.status(400).json({ message: 'Hesap daha önce doğrulanmış!' });
    }

    if (status == 2) {
      try {
        // Emakin Trigger
        const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/trigger', {
          apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
          logonId: "support@bt.guru",
          logonProvider: "Organization",
          eventName: "VerifyTFACode." + customerId,
          inputData: null,
          testMode: false,
          culture: null
        });

        return res.status(200).json({ auth: true, message: 'Hesabınız başarılı şekilde doğrulandı.', status: status, sessionToken: token });
      } catch (err) {
        console.log({ message: 'Hesap doğrulanamadı!', error: err.message });
        return res.status(500).json({ message: 'Hesap doğrulanamadı!', error: err.message });
      }

    }

  } catch (err) {
    console.log({ message: 'Hesap doğrulanamadı.', error: err.message });
    return res.status(500).json({ message: 'Hesap doğrulanamadı.', error: err.message });
  }
});

// Price List endpoint
app.get('/price-list', async (req, res) => {

  try {
    const resultAssets = await pool.query(`SELECT 
      "TokenType" as token, 
      "Icon" as icon, 
      "UnitPrice" as price, 
      "Ratio" as ratio, 
      "RatioType" as "ratioType" 
      FROM  "` + PREFIX + `POAssets"`);
    var assetList = resultAssets.rows;

    const resultCoins = await pool.query(`SELECT 
        "Name" as token, 
        "Icon" as icon, 
        "UnitPrice" as price, 
        "Ratio" as ratio, 
        "RatioType" as "ratioType" 
        FROM  "` + PREFIX + `POCoins"`);
    var coinList = resultCoins.rows;

    var priceList = assetList.concat(coinList);
    priceList.forEach(item => {
      item.price = parseFloat(item.price).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 4 });
    });

    return res.status(200).json(priceList);
  } catch (err) {
    console.log({ message: 'Token fiyat listesi alınamadı!', hata: err.message });
    return res.status(500).json({ message: 'Token fiyat listesi alınamadı!', hata: err.message });
  }
});

// Customer Balance endpoint
app.get('/balances', authMiddleware, async (req, res) => {

  try {
    const customerId = req.user?.customerId;
    const result = await pool.query(`SELECT 
      CONCAT(a."TokenName", ' - ' , b."Type") AS "Asset", 
      b."Amount", 
      a."UnitPrice" 
      FROM "` + PREFIX + `CustomerBalances" b 
      LEFT JOIN "` + PREFIX + `Customers" c ON c."Id" = b."CustomerId" 
      LEFT JOIN "` + PREFIX + `POAssets" a ON a."TokenType" = b."Type" 
      WHERE c."Id" = $1 AND b."Type" != $2`, [customerId, "TL"]);
    const resultTL = await pool.query(`SELECT "Amount" FROM "` + PREFIX + `CustomerBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, "TL"]);

    var TLpurchasingPower = resultTL.rowCount == 0 ? 0 : resultTL.rows[0].Amount;

    var balances = [];
    var assets = [];
    var totalbalance = 0;

    for (let i = 0; i < result.rows.length; i++) {

      //var assetAmount = result.rows[i].Amount < 0.01 ? Number(result.rows[i].Amount).toLocaleString('tr-TR', {maximumFractionDigits:4}) : Number(result.rows[i].Amount).toLocaleString('tr-TR', {maximumFractionDigits:2})

      var item = {

        assetName: result.rows[i].Asset,
        amount: Number(result.rows[i].Amount).toLocaleString('tr-TR', { maximumFractionDigits: 4 }),
        unitPrice: Number(result.rows[i].UnitPrice).toLocaleString('tr-TR', { maximumFractionDigits: 2 }),
        totalPrice: (result.rows[i].Amount * result.rows[i].UnitPrice).toLocaleString('tr-TR', { maximumFractionDigits: 2 })
      }

      totalbalance += result.rows[i].Amount * result.rows[i].UnitPrice;

      assets.push(item);
    }

    totalbalance += Number(TLpurchasingPower);

    var balances = {
      totalBalance: totalbalance.toLocaleString('tr-TR', { maximumFractionDigits: 2 }),
      purchasingAsset: {

        assetName: "TL",
        amount: Number(TLpurchasingPower).toLocaleString('tr-TR', { maximumFractionDigits: 2 })
      },
      assets: assets
    }

    return res.status(200).json(balances);
  } catch (err) {
    console.log({ message: 'Bakiye servis hatası!', hata: err.message });
    return res.status(500).json({ message: 'Bakiye servis hatası!', hata: err.message });
  }
});

// Customer Asset Balance endpoint
app.get('/asset-balance', authMiddleware, async (req, res) => {
  const { assetType } = req.query;
  const customerId = req.user?.customerId;

  try {

    const result = await pool.query(`SELECT 
      "Type", 
      "Amount"
      FROM "` + PREFIX + `CustomerBalances"
      WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, assetType]);

    var assetBalance = result.rowCount == 0 ? 0 : Number(result.rows[0].Amount);
    assetBalance = assetBalance.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });

    return res.status(200).json({ assetBalance: assetBalance });
  } catch (err) {
    console.log({ message: 'Bakiye servis hatası!', hata: err.message });
    return res.status(500).json({ message: 'Bakiye servis hatası!', hata: err.message });
  }
});

// Customer Transactions endpoint
app.get('/transactions', authMiddleware, async (req, res) => {
  const { type } = req.query;  // 1: Alış  2: Satış  3: Tümü  4: Para Yatırma  5: Para Çekme  6: Tümü  8:SessionLogs
  const customerId = req.user?.customerId;

  if (type == 1 || type == 2 || type == 3) {
    
    var queryAddition = "";
    var transactions = [];

    async function getTransactions(unitPrice, queryAddition) {
      
      const result = await pool.query(`SELECT 
        CONCAT(t."FromAsset", ' / ' , t."ToAsset") AS "parity", 
        l."Name" AS "type", 
        t."Amount" AS "amount",
        t."`+unitPrice+`" AS "unitPrice", 
        t."FeeRatio" AS "feeRatio",
        t."FeeAmount" AS "feeAmount", 
        t."ContributionMargin" AS "contributionMargin", 
        t."TotalPrice" AS "totalPrice",
        t."TransactionDate" AS "date"
        FROM "` + PREFIX + `CustomerTransactions" t 
        LEFT JOIN "` + PREFIX + `POAssets" a1 ON a1."Id" = t."FromTypeId" 
        LEFT JOIN "` + PREFIX + `POAssets" a2 ON a2."Id" = t."ToTypeId" 
        LEFT JOIN "` + PREFIX + `POLookUps" l ON l."Code" = t."TransactionType"
        WHERE t."CustomerId" = $1 ` + queryAddition, [customerId]);

      var transactions = result.rows;
        

      function formatNumber(value) {
        return parseFloat(value).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 4 });
      }

      transactions.forEach(item => {
        item.amount = formatNumber(item.amount);
        item.unitPrice = formatNumber(item.unitPrice);
        item.feeRatio = formatNumber(item.feeRatio);
        item.feeAmount = formatNumber(item.feeAmount);
        item.contributionMargin = formatNumber(item.contributionMargin);
        item.totalPrice = formatNumber(item.totalPrice);
      });

      return transactions;
    }

    try {

      if (type == 1) {

         queryAddition = `AND t."TransactionType" = '1'`; 
         transactions = getTransactions("ToUnitPrice", queryAddition);
      }
      else if (type == 2) { 

        queryAddition = `AND t."TransactionType" = '2'`; 
        transactions = getTransactions("FromUnitPrice", queryAddition); 
      }
      else if (type == 3) { 

        var transactionsBuy = [];
        var queryAdditionBuy = `AND t."TransactionType" = '1'`; 
        transactionsBuy = await getTransactions("ToUnitPrice", queryAdditionBuy);

        var transactionsSell = [];
        var queryAdditionSell = `AND t."TransactionType" = '2'`; 
        transactionsSell = await getTransactions("FromUnitPrice", queryAdditionSell);

        transactions = transactionsBuy.concat(transactionsSell);
      }
      return res.status(200).json(transactions);
    } catch (err) {
      console.log({ message: 'Hesap hareketleri servis hatası!', hata: err.message, IP: req.ip });
      return res.status(500).json({ message: 'Hesap hareketleri servis hatası!', hata: err.message });
    }
  }

  else if (type == 4 || type == 5 || type == 6) {

    if (type == 4) { queryAddition = `AND t."TransactionType" = '3'` }
    else if (type == 5) { queryAddition = `AND t."TransactionType" = '4'` }
    else if (type == 6) { queryAddition = `AND t."TransactionType" = '3' OR t."TransactionType" = '4'` }

    try {
      const customerId = req.user?.customerId;
      const result = await pool.query(`SELECT
        l1."Name" AS "bankName",
        a."IBAN" AS "iban",
        l2."Name" AS "type",
        t."TotalPrice" AS "totalPrice",
        t."TransactionDate" AS "date"
        FROM "` + PREFIX + `CustomerTransactions" t 
        LEFT JOIN "` + PREFIX + `CustomerBankAccounts" a ON a."CustomerId" = t."CustomerId" 
        LEFT JOIN "` + PREFIX + `POLookUps" l1 ON t."BankId" = l1."Id" 
        LEFT JOIN "` + PREFIX + `POLookUps" l2 ON (l2."Code" = t."TransactionType" AND l2."Type" = 'TRANSACTION')
        WHERE t."CustomerId" = $1 ` + queryAddition, [customerId]);

      var transactions = result.rows;

      function formatNumber(value) {
        return parseFloat(value).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 4 });
      }

      transactions.forEach(item => {
        item.totalPrice = formatNumber(item.totalPrice);
      });

      return res.status(200).json(transactions);
    } catch (err) {
      return res.status(500).json({ message: 'Hesap hareketleri servis hatası!', hata: err.message });
    }

  }

  else if (type == 8){
    //işlem tipi - IP numarası - Tarih
    const result = await pool.query(`SELECT 
      CONCAT(t."FromAsset", ' / ' , t."ToAsset") AS "parity", 
      l."Name" AS "type", 
      t."Amount" AS "amount",
      t."`+unitPrice+`" AS "unitPrice", 
      t."FeeRatio" AS "feeRatio",
      t."FeeAmount" AS "feeAmount", 
      t."ContributionMargin" AS "contributionMargin", 
      t."TotalPrice" AS "totalPrice",
      t."TransactionDate" AS "date"
      FROM "` + PREFIX + `CustomerTransactions" t 
      LEFT JOIN "` + PREFIX + `POAssets" a1 ON a1."Id" = t."FromTypeId" 
      LEFT JOIN "` + PREFIX + `POAssets" a2 ON a2."Id" = t."ToTypeId" 
      LEFT JOIN "` + PREFIX + `POLookUps" l ON l."Code" = t."TransactionType"
      WHERE t."CustomerId" = $1 ` + queryAddition, [customerId]);


  }


});

// Şifre sıfırlama talep endpointi
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Kullanıcının e-posta adresinin veritabanında olup olmadığını kontrol et
    const result = await pool.query('SELECT * FROM "' + PREFIX + 'Customers" WHERE "EmailAddress" = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      console.log({ message: 'Kullanıcı bulunamadı.' });
      return res.status(400).json({ message: 'Kullanıcı bulunamadı.' });
    }

    // Şifre sıfırlama token'i oluştur
    const resetToken = CryptoJS.lib.WordArray.random(20);
    const d = Date.now();

    //initiate Emakin Mail Sender
    try {
      const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/initiateByProcess', {
        apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
        logonId: "support@bt.guru",
        logonProvider: "Organization",
        process: "c45309be-a1f7-4ef9-bf81-c695772911cc",
        task: "2ceae5e4-93f1-468a-a39f-c09f8d101319",
        version: null,
        data: `<PasswordManagement>
                  <ResetPassword>
                    <Id/>
                    <CustomerId>${user.Id}</CustomerId>
                    <EmailAddress>${email}</EmailAddress>
                    <Token>${resetToken}</Token>
                    <TokenExpireDate></TokenExpireDate>
                    <Password></Password>
                    <UpdateDate></UpdateDate>
                </ResetPassword>
              </PasswordManagement>`,
        culture: null
      });

    } catch (error) {
      console.log({ message: 'Parola sıfırlama maili gönderilemedi.', error: error.message })
      return res.status(500).json({ message: 'Parola sıfırlama maili gönderilemedi.', error: error.message });
    }

    return res.status(200).json({ message: 'Parola sıfırlama maili gönderildi.' });
  } catch (err) {
    console.log({ message: 'Parola sıfırlama maili gönderilemedi.', error: err.message });
    return res.status(500).json({ message: 'Parola sıfırlama maili gönderilemedi.', error: err.message });
  }
});

// Şifre sıfırlama endpointi
app.post('/reset-password', async (req, res) => {
  const resetToken = req.header('reset-token');
  const { password, confirmPassword } = req.body;

  try {
    // Token doğrulama ve kullanıcıyı bulma
    const result = await pool.query('SELECT prl."CustomerId" AS "CustomerId", c."HashedPassword" AS "OldHashedPassword", prl."Status" AS "Status" FROM "' + PREFIX + 'CustomerPasswordResetLogs" prl INNER JOIN "' + PREFIX + 'Customers" c ON c."Id" = prl."CustomerId" WHERE prl."Token" = $1 AND prl."TokenExpireDate" > $2', [resetToken, new Date()]);

    const passwordResetLog = result.rows[0];
    const passwordRegex = /^(?=.*[a-zçğıöşü])(?=.*[A-ZÇĞİÖŞÜ])(?=.*[@$!%*?&.,;:])[A-Za-zçÇğĞıİöÖşŞüÜ\d@$!%*?&.,;:]{8,}$/;
    const hashedPassword = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);

    if (!passwordResetLog) {
      console.log({ message: 'Geçersiz token.' });
      return res.status(400).json({ message: 'Geçersiz token.' });
    }

    if (!password || !passwordRegex.test(password)) {
      console.log({ message: 'Şifrenizi geçerli formatta giriniz.' });
      return res.status(400).json({ message: 'Şifrenizi geçerli formatta giriniz.' });
    }

    if (password != confirmPassword) {
      console.log({ message: 'Şifreler eşleşmiyor.' });
      return res.status(400).json({ message: 'Şifreler eşleşmiyor.' });
    }

    if (hashedPassword === passwordResetLog.OldHashedPassword) {
      console.log({ message: 'Şifreniz bir önceki şifreniz ile aynı olamaz.' });
      return res.status(400).json({ message: 'Şifreniz bir önceki şifreniz ile aynı olamaz.' });
    }

    if (passwordResetLog.Status != 'Active') {
      console.log({ message: 'Geçersiz Token (Expired).' });
      return res.status(400).json({ message: 'Geçersiz Token (Expired).' });
    }

    //trigger Emakin Event Listener
    try {
      const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/trigger', {
        apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
        logonId: "support@bt.guru",
        logonProvider: "Organization",
        eventName: "ResetPassword." + resetToken,
        inputData: `<PasswordManagement>
                  <ResetPassword>
                    <CustomerId>${passwordResetLog.CustomerId}</CustomerId>
                    <HashedPassword>${hashedPassword}</HashedPassword>
                    <IPAddress>${req.ip}</IPAddress>
                </ResetPassword>
              </PasswordManagement>`,
        testMode: false,
        culture: null
      });

    } catch (error) {
      console.log({ message: 'Şifre sıfırlama başarısız.', error: error.response.data });
      return res.status(500).json({ message: 'Şifre sıfırlama başarısız.', error: error.response.data });
    }

    return res.status(200).json({ message: 'Şifreniz başarılı şekilde sıfırlandı.' });
  } catch (err) {
    console.log({ message: 'Şifre sıfırlama başarısız', error: err.message });
    return res.status(500).json({ message: 'Şifre sıfırlama başarısız', error: err.message });
  }
});

// Mint-Burn token endpointi
app.post('/token-operation', authMiddleware, async (req, res) => {
  const { assetType, operationType, assetAmount, unitPrice } = req.body;

  try {
    const customerId = req.user?.customerId;

    const resultTL = await pool.query(`SELECT "Amount" FROM "` + PREFIX + `CustomerBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, "TL"]);
    if (resultTL.rowCount == 0) {
      console.log({ message: "Hesap bakiyesi yeterli değil." });
      return res.status(400).json({ message: "Hesap bakiyesi yeterli değil." });
    }
    const balanceTL = resultTL.rows[0].Amount;

    const resultMTLK = await pool.query(`SELECT "Amount" FROM "` + PREFIX + `CustomerBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, assetType]);
    const balanceMTLK = resultMTLK.rows[0].Amount;

    const resultUnitPrice = await pool.query(`SELECT "FeeAmount", "ContributionMargin" FROM "` + PREFIX + `POAssets" WHERE "TokenType" = 'MTLK' `);
    const feeAmount = Number(resultUnitPrice.rows[0].FeeAmount);
    const contributionMargin = Number(resultUnitPrice.rows[0].ContributionMargin);

    const fee = (feeAmount * assetAmount * unitPrice);
    const fixedFee = fee.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
    const totalAmount = (assetAmount * unitPrice * (1 + feeAmount) + contributionMargin);
    const fixedTotalAmount = totalAmount.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

    if (operationType == 1 && totalAmount > balanceTL) { //MİNT 
      console.log({ message: "Hesap bakiyesi yeterli değil." });
      return res.status(400).json({ message: "Hesap bakiyesi yeterli değil." });
    }

    if (operationType == 2 && assetAmount > balanceMTLK) { //BURN
      console.log({ message: "Hesap bakiyesi yeterli değil." });
      return res.status(400).json({ message: "Hesap bakiyesi yeterli değil." });
    }

    //initiate Emakin Start Token Operation (Mint)
    try {
      const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/initiateByProcess', {
        apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
        logonId: "support@bt.guru",
        logonProvider: "Organization",
        process: "329ab0d6-747d-4826-b809-8ad08644f512",
        task: "dbabcc6e-a4f5-4800-9cf8-84bbfd764b68",
        version: null,
        data: `<AssetOperationManagement>
                  <CustomerInformation>
                    <CustomerId>${customerId}</CustomerId>
                  </CustomerInformation>
                  <BalanceInformation>
                    <AssetType>${assetType}</AssetType>
                    <OperationType>${operationType}</OperationType>
                    <AssetAmount>${assetAmount}</AssetAmount>
                    <UnitPrice>${unitPrice}</UnitPrice>
                    <ContributionMargin>${contributionMargin}</ContributionMargin>
                    <Fee>${fixedFee}</Fee>
                    <Type/>
                    <TotalAmount>${fixedTotalAmount}</TotalAmount>
                  </BalanceInformation>
                </AssetOperationManagement>`,
        culture: null
      });

    } catch (error) {
      console.log({ message: 'İşlem emri iletimi başarısız!', hata: error.response.data });
      return res.status(500).json({ message: 'İşlem emri iletimi başarısız!', hata: error.response.data });
    }

    return res.status(200).json({ message: 'İşlem emri başarılı şekilde oluşturuldu.' });
  } catch (err) {
    console.log({ message: 'İşlem emri oluşturulamadı!', hata: err.message });
    return res.status(500).json({ message: 'İşlem emri oluşturulamadı!', hata: err.message });
  }

});

// Calculate endpointi
app.post("/calculate", authMiddleware, async (req, res) => {

  const { action, fromType, toType, amount } = req.body;
  const customerId = req.user?.customerId;

  const resultUnitPrice = await pool.query(`SELECT "UnitPrice", "FeeAmount", "ContributionMargin" FROM "` + PREFIX + `POAssets" WHERE "TokenType" = 'MTLK' `);
  const unitPrice = Number(resultUnitPrice.rows[0].UnitPrice);
  var fixedUnitPrice = unitPrice.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });

  const feeAmount = Number(resultUnitPrice.rows[0].FeeAmount);
  const contributionMargin = Number(resultUnitPrice.rows[0].ContributionMargin);

  const resultCustomerTLBalance = await pool.query(`SELECT "Amount" FROM "` + PREFIX + `CustomerBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, "TL"]);
  const resultCustomerMTLKBalance = await pool.query(`SELECT "Amount" FROM "` + PREFIX + `CustomerBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, "MTLK"]);

  var customerTLBalance = resultCustomerTLBalance.rowCount < 1 ? 0 : Number(resultCustomerTLBalance.rows[0].Amount);
  var customerMTLKBalance = resultCustomerMTLKBalance.rowCount < 1 ? 0 : Number(resultCustomerMTLKBalance.rows[0].Amount);

  var result = 0;
  var reCalculatedAmount = 0;
  var fee = 0

  if (action == "buy") {

    try {

      if (amount <= 0) {
        console.log({ message: 'Hatalı tutar girdiniz!' });
        return res.status(400).json({ message: 'Hatalı tutar girdiniz!' })
      }

      if (fromType == "TL" && toType == "MTLK") {

        reCalculatedAmount = (amount - contributionMargin) / (1 + feeAmount) / unitPrice;
        var floorReCalculatedAmount = Math.floor(reCalculatedAmount);
        var fixedFloorReCalculatedAmount = floorReCalculatedAmount.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });

        fee = ((reCalculatedAmount * unitPrice) * feeAmount);
        const fixedFee = fee.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });
        const fixedContributionMargin = contributionMargin.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

        result = (floorReCalculatedAmount * unitPrice * (1 + feeAmount) + contributionMargin).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 }); // (9 * 101)1.002 + 10


        if (amount < (unitPrice * (1 + feeAmount) + contributionMargin)) {
          console.log({ message: 'En az 1 MTLK tutarı ile işlem yapabilirsiniz.' });
          return res.status(400).json({ message: 'En az 1 MTLK tutarı ile işlem yapabilirsiniz.' })
        }

        if (customerTLBalance < (reCalculatedAmount * unitPrice * (1 + feeAmount) + 10)) {
          reCalculatedAmount = (customerTLBalance - contributionMargin) / (1 + feeAmount) / unitPrice;
          reCalculatedAmount = Math.floor(reCalculatedAmount);
          fixedReCalculatedAmount = reCalculatedAmount.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });

          var purchasingPower = (reCalculatedAmount * unitPrice * (1 + feeAmount) + 10);
          var fixedPurchasingPower = purchasingPower.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
          console.log({ message: "Yetersiz bakiye! En fazla " + fixedPurchasingPower + " TL'lik işlem yapabilirsiniz" });
          return res.status(400).json({ message: "Yetersiz bakiye! En fazla " + fixedPurchasingPower + " TL'lik işlem yapabilirsiniz" });
        }

        return res.status(200).json({ totalAmount: result, fee: fixedFee, contributionMargin: fixedContributionMargin, reCalculatedAmount: fixedFloorReCalculatedAmount, fromUnitPrice: fixedUnitPrice });

      } else if (fromType == "MTLK" && toType == "TL") {

        if (!isInt(amount)) {
          console.log({ message: 'Hatalı tutar girdiniz!' });
          return res.status(400).json({ message: 'Hatalı tutar girdiniz!' });
        }

        function isInt(value) {
          return !isNaN(value) &&
            parseInt(Number(value)) == value &&
            !isNaN(parseInt(value, 10));
        }

        result = ((amount * unitPrice) * (1 + feeAmount) + contributionMargin).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

        fee = (amount * unitPrice * (feeAmount));
        const fixedFee = fee.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
        const fixedContributionMargin = contributionMargin.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

        if (customerTLBalance < ((amount * unitPrice) * (1 + feeAmount) + contributionMargin)) {
          console.log({ message: 'Yetersiz Bakiye!' });
          return res.status(400).json({ message: 'Yetersiz Bakiye!' })
        }

        return res.status(200).json({ totalAmount: result, fee: fixedFee, contributionMargin: fixedContributionMargin, reCalculatedAmount: amount, fromUnitPrice: unitPrice });

      } else {
        console.log({ message: 'Geçersiz varlık tipi.' });
        return res.status(400).json({ message: 'Geçersiz varlık tipi.' })
      }


    } catch (error) {
      console.log({ message: "Tutar hesaplanamadı!", hata: error.message });
      return res.status(500).json({ message: "Tutar hesaplanamadı!", hata: error.message })
    }
  }
  else if (action == "sell") {

    try {

      if (amount <= 0) {
        console.log({ message: 'Hatalı tutar girdiniz!' });
        return res.status(400).json({ message: 'Hatalı tutar girdiniz!' })
      }

      if (fromType == "TL" && toType == "MTLK") {

        reCalculatedAmount = (amount - contributionMargin) / (1 + feeAmount) / unitPrice;
        reCalculatedAmount = Math.floor(reCalculatedAmount);
        var fixedReCalculatedAmount = reCalculatedAmount.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });

        fee = ((reCalculatedAmount * unitPrice) * feeAmount);
        const fixedFee = fee.toLocaleString('tr-TR', { maximumFractionDigits: 4, minimumFractionDigits: 2 });
        const fixedContributionMargin = contributionMargin.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

        if (amount < (unitPrice * (1 + feeAmount) + contributionMargin)) {
          console.log({ message: 'En az 1 MTLK tutarı ile işlem yapabilirsiniz.' });
          return res.status(400).json({ message: 'En az 1 MTLK tutarı ile işlem yapabilirsiniz.' })
        }

        if (customerMTLKBalance < reCalculatedAmount) {
          console.log({ message: 'Yetersiz bakiye!' });
          return res.status(400).json({ message: 'Yetersiz bakiye!' });
        }

        result = (reCalculatedAmount * unitPrice * (1 + feeAmount) + contributionMargin).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 }); // (9 * 101)1.002 + 10
        return res.status(200).json({ totalAmount: result, fee: fixedFee, contributionMargin: fixedContributionMargin, reCalculatedAmount: fixedReCalculatedAmount, fromUnitPrice: fixedUnitPrice });

      } else if (fromType == "MTLK" && toType == "TL") {

        if (!isInt(amount)) {
          console.log({ message: 'Hatalı tutar girdiniz!' });
          return res.status(400).json({ message: 'Hatalı tutar girdiniz!' });
        }

        function isInt(value) {
          return !isNaN(value) &&
            parseInt(Number(value)) == value &&
            !isNaN(parseInt(value, 10));
        }

        result = ((amount * unitPrice) * (1 + feeAmount) + contributionMargin).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

        fee = (amount * unitPrice * (1 + feeAmount));
        const fixedFee = fee.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
        const fixedContributionMargin = contributionMargin.toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

        if (customerMTLKBalance < amount) {
          console.log({ message: 'Yetersiz Bakiye!' });
          return res.status(400).json({ message: 'Yetersiz Bakiye!' })
        }

        return res.status(200).json({ totalAmount: result, fee: fixedFee, contributionMargin: fixedContributionMargin, reCalculatedAmount: amount, fromUnitPrice: unitPrice });

      } else {
        console.log({ message: 'Geçersiz varlık tipi.' });
        return res.status(400).json({ message: 'Geçersiz varlık tipi.' })
      }


    } catch (error) {
      console.log();
      return res.status(500).json({ message: "Tutar hesaplanamadı!", hata: error.message })
    }

  }

})

app.post("/contact-us", async (req, res) => {
  const { email, name, surname, phoneNumber, message } = req.body;

  try {
    const response = await axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/initiateByProcess', {
      apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
      logonId: "support@bt.guru",
      logonProvider: "Organization",
      process: "055ed287-0b4b-4586-8710-3b12ddb13c18",
      task: "03fad685-55ba-4ade-b23b-f180f0e3ff8c",
      version: null,
      data: `<ContactUsManagement>
                  <EmailAddress>${email}</EmailAddress>
                  <Name>${name}</Name>
                  <Surname>${surname}</Surname>
                  <PhoneNumber>${phoneNumber}</PhoneNumber>
                  <Message>${message}</Message>
            </ContactUsManagement>`,
      culture: null
    });
    return res.status(200).json({ message: 'Bize ulaşın talebi iletildi.' });

  } catch (error) {
    console.log({ message: 'Bize ulaşın talebi iletilemedi.', error: error.message });
    return res.status(500).json({ message: 'Bize ulaşın talebi iletilemedi.', error: error.message });
  }
})

function tckn_dogrula(tckn) {
  // geleni her zaman String'e çevirelim!
  tckn = String(tckn);

  // tckn '0' karakteri ile başlayamaz!
  if (tckn.substring(0, 1) === '0') {
    return false;
  }
  // tckn 11 karakter uzunluğunda olmalı!
  if (tckn.length !== 11) {
    return false;
  }

  /**
      Aşağıdaki iki kontrol için toplamları hazır ediyoruz
      - o anki karakteri sayıya dönüştür
      - tek haneleri ayrıca topla (1,3,5,7,9)
      - çift haneleri ayrıca topla (2,4,6,8)
      - bütün haneleri ayrıca topla
  **/
  var ilkon_array = tckn.substr(0, 10).split('');
  var ilkon_total = hane_tek = hane_cift = 0;

  for (var i = j = 0; i < 9; ++i) {
    j = parseInt(ilkon_array[i], 10);
    if (i & 1) { // tek ise, tcnin çift haneleri toplanmalı!
      hane_cift += j;
    } else {
      hane_tek += j;
    }
    ilkon_total += j;
  }

  /**
      KONTROL 1:
      1. 3. 5. 7. ve 9. hanelerin toplamının 7 katından, 
      2. 4. 6. ve 8. hanelerin toplamı çıkartıldığında, 
      elde edilen sonucun Mod10'u bize 10. haneyi verir
  **/
  if ((hane_tek * 7 - hane_cift) % 10 !== parseInt(tckn.substr(-2, 1), 10)) {
    return false;
  }

  /**
      KONTROL 2:
      1. 2. 3. 4. 5. 6. 7. 8. 9. ve 10. hanelerin toplamından
      elde edilen sonucun Mod10'u bize 11. haneyi vermelidir.
      NOT: ilk 9 haneyi üstteki FOR döndüsünde zaten topladık!
  **/
  ilkon_total += parseInt(ilkon_array[9], 10);
  if (ilkon_total % 10 !== parseInt(tckn.substr(-1), 10)) {
    return false;
  }

  return true;
}

// Captcha doğrulama fonksiyonu
const verifyCaptcha = async (recaptchaToken) => {

  return axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
    params: {
      secret: captchaSecretKey,
      response: recaptchaToken
    }
  });
};

const initiateProcess = async (userData) => {
  const { identityNumber, name, surname, birthDate, email, phoneNumber, password } = userData;

  return axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/initiateByProcess', {
    apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
    logonId: "support@bt.guru",
    logonProvider: "Organization",
    process: "7fed06da-1969-4c52-9534-df2c58151fa5",
    task: "4661a64d-53c2-4584-86d4-48f26a481f6d",
    version: null,
    data: `<CustomerOnboarding>
            <IdentityNumber>${identityNumber}</IdentityNumber>
            <Name>${name}</Name>
            <Surname>${surname}</Surname>
            <BirthDate>${birthDate}</BirthDate>
            <EmailAddress>${email}</EmailAddress>
            <PhoneNumber>${phoneNumber}</PhoneNumber>
            <Password>${password}</Password>
          </CustomerOnboarding>`,
    culture: null
  });
};

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servis ayağa kalktı, PORT:${PORT}`);
});


