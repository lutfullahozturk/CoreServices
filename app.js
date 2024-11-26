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

  const sourceApiKeys = await pool.query('SELECT "Id" FROM "' + PREFIX + 'APIKeys" WHERE "Code" = $1', [API_KEY_CODE])
  const sourceApiKey = sourceApiKeys.rows[0].Id;

  if (apiKey && apiKey === sourceApiKey) {
    next();
  } else {
    res.status(401).json({ message: 'Yetkisiz erişim: API anahtarı hatalı.' });
  }
};

const authMiddleware = (req, res, next) => {
  const token = req.headers['x-access-token'];  // Token'i istek başlığından al

  if (!token) {
    return res.status(403).json({ message: 'Session token gönderilmedi.' });
  }

  // Token'i doğrula
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
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
      return res.status(400).json({ message: 'Geçerli bir e-posta adresi giriniz.' });
    }
    if (!name || !nameSurnameRegex.test(name)) {
      return res.status(400).json({ message: 'Adınızı geçerli formatta giriniz.' });
    }
    if (!surname || !nameSurnameRegex.test(surname)) {
      return res.status(400).json({ message: 'Soyadınızı geçerli formatta giriniz.' });
    }
    if (!birthDate || !birthDateRegex.test(birthDate)) {
      return res.status(400).json({ message: 'Doğum tarihinizi geçerli formatta giriniz.' });
    }
    if (!phoneNumber || !phoneNumberRegex.test(phoneNumber)) {
      return res.status(400).json({ message: 'Telefon numaranızı geçerli formatta giriniz.' });
    }
    if (!password || !passwordRegex.test(password)) {
      return res.status(400).json({ message: 'Parolanızı geçerli formatta giriniz.' });
    }
    if (password != confirmPassword) {
      return res.status(400).json({ message: 'Parolalar eşleşmiyor.' });
    }

    // CAPCTHA kontrolü
    try {
      const verifyCaptchaResponse = await verifyCaptcha(recaptchaToken);
      if (!verifyCaptchaResponse.data.success) {
        return res.status(400).json({ code: 2, message: "reCAPTCHA doğrulaması başarısız." })
      }
    }
    catch (captchaError) {
      res.status(500).json({ code: 2, message: "reCAPTCHA doğrulaması sırasında bir hata oluştu." })
    }

    // E-posta kontrolü
    const emailCheck = await pool.query('SELECT * FROM "' + PREFIX + 'Customers" WHERE "EmailAddress" = $1', [email]);
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Bu mail adresi daha önce kaydedilmiş, lütfen giriş yapınız.' });
    }

    //TCKN format kontrolü
    const tcknDogrula = tckn_dogrula(identityNumber);
    if (!identityNumber || !tcknDogrula) {
      return res.status(400).json({ message: 'Geçerli bir kimlik numarası giriniz.' });
    }

    // IdentityNumber kontrolü
    const identityCheck = await pool.query('SELECT * FROM "' + PREFIX + 'Customers" WHERE "IdentityNumber" = $1', [identityNumber]);
    if (identityCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Bu kimlik numarası daha önce kaydedilmiş, lütfen giriş yapınız.' });
    }

    try {
      const initiateResponse = await initiateProcess(req.body);
      res.status(201).json({ message: 'Kullanıcı başarılı şekilde kaydedildi.', email: email });
    }
    catch (initiateerror) {
      res.status(400).json({ message: 'Girdiğiniz bilgiler ile kimlik bilgileri doğrulanamadı. Lütfen bilgilerinizi kontrol ederek yeniden deneyiniz.' })
    }


  } catch (err) {
    res.status(500).json({ message: 'Kayıt gerçekleştirilemedi.', hata: err.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password, recaptchaToken } = req.body;

  try {
    const result = await pool.query('SELECT "Id", "Name", "Surname", "EmailAddress", "HashedPassword","EmailVerificationStatus" ,"AMLStatus" FROM "' + PREFIX + 'Customers" WHERE "EmailAddress" = $1', [email]);
    const user = result.rows[0];

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    var hashedPassword = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);

    try {
      const verifyCaptchaResponse = await verifyCaptcha(recaptchaToken);
      if (!verifyCaptchaResponse.data.success) {
        return res.status(400).json({ code: 2, message: "reCAPTCHA doğrulaması başarısız." })
      }
    }
    catch (captchaError) {
      res.status(500).json({ code: 2, message: "reCAPTCHA doğrulaması sırasında bir hata oluştu.", error: captchaError.message })
    }

    // Email regex'e uygun mu kontrolü
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({ message: 'Geçerli bir e-posta adresi giriniz.' });
    }

    if (!user) {
      return res.status(400).json({ message: 'Email ya da şifre hatalı.' });
    }

    if (user.HashedPassword != hashedPassword) {
      return res.status(400).json({ message: 'Email ya da şifre hatalı.' });
    }

    if (user.EmailVerificationStatus == 0) {
      return res.status(400).json({ message: 'Hesabınız doğrulanamadı, doğrulamanın ardından giriş yapabilirsiniz.' });
    }

    if (user.AMLStatus == 0) {
      return res.status(400).json({ message: 'Başvurunuz değerlendiriliyor, başvurunuzun olumlu sonuçlanmasının ardından giriş yapabilirsiniz.' });
    }
    else if (user.AMLStatus == 2) {
      return res.status(400).json({ message: 'Başvurunuz olumsuz sonuçlanmıştır, giriş yapamazsınız.' });
    }

    const token = jwt.sign({ customerId: user.Id, email: user.EmailAddress, nameSurname: (user.Name + ' ' + user.Surname) }, SECRET_KEY, { expiresIn: 7200 });
    res.status(200).json({ auth: true, message: 'Giriş başarılı.', sessionToken: token });
  } catch (err) {
    res.status(500).json({ message: 'Giriş yapılamadı.', hata: err.message });
  }
});

// 2FA endpoint
app.post('/twofactorauth', async (req, res) => {
  const { email, code } = req.body;

  try {
    const result = await pool.query('SELECT "EmailVerificationCode" FROM "' + PREFIX + 'Customers" WHERE "EmailAddress" = $1', [email]);
    const user = result.rows[0];

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // Email regex'e uygun mu kontrolü
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({ message: 'Geçerli bir e-posta adresi giriniz.' });
    }

    if (!user) {
      return res.status(400).json({ message: 'Email adresi bulunamadı.' });
    }

    if (code != user.EmailVerificationCode) {
      return res.status(400).json({ message: 'Girilen kod hatalı.' });
    }

    const triggerResponse = await triggerProcess(true, email);
    res.status(200).json({ auth: true, message: 'Hesabınız başarılı şekilde doğrulandı.' });
  } catch (err) {
    res.status(500).json({ message: 'Hesap doğrulanamadı.', hata: err.message });
  }
});

// Price List endpoint
app.get('/price-list', async (req, res) => {
  try {
    const result = await pool.query('SELECT "Type" as token, "Icon" as icon, "UnitPrice" as price, "Ratio" as ratio, "RatioType" as "ratioType" FROM  "' + PREFIX + 'Assets"');
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Token fiyat listesi boş.' });
    }
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Token fiyat listesi alınamadı!', hata: err.message });
  }
});

// Customer Balance endpoint
app.get('/balances', authMiddleware, async (req, res) => {

  try {
    const customerId = req.user?.customerId;
    const result = await pool.query(`SELECT CONCAT(a."Name", ' - ' , b."Type") AS "Asset", b."Amount", a."UnitPrice" FROM "rcoretestTokBalances" b INNER JOIN "rcoretestTokCustomers" c ON c."Id" = b."CustomerId" INNER JOIN "rcoretestTokAssets" a ON a."Type" = b."Type" WHERE c."Id" = $1`, [customerId]);
    const resultTL = await pool.query(`SELECT "Amount" FROM "rcoretestTokBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, "TL"]);

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

    var balances = {
      totalBalance: totalbalance.toLocaleString('tr-TR', { maximumFractionDigits: 2 }),
      purchasingAsset: {

        assetName: "TL",
        amount: Number(TLpurchasingPower).toLocaleString('tr-TR', { maximumFractionDigits: 2 })
      },
      assets: assets
    }

    res.status(200).json(balances);
  } catch (err) {
    res.status(500).json({ message: 'Bakiye servis hatası!', hata: err.message });
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
      res.status(500).json({ message: 'Parola sıfırlama maili gönderilemedi.', error: error.response.data });
    }


    res.status(200).json({ message: 'Parola sıfırlama maili gönderildi.' });
  } catch (err) {
    res.status(500).json({ message: 'Parola sıfırlama maili gönderilemedi.', error: err.message });
  }
});

// Şifre sıfırlama endpointi
app.post('/reset-password', async (req, res) => {
  const resetToken = req.header('reset-token');
  const { password, confirmPassword } = req.body;

  try {
    // Token doğrulama ve kullanıcıyı bulma
    const result = await pool.query('SELECT prl."CustomerId" AS "CustomerId", c."HashedPassword" AS "OldHashedPassword", prl."Status" AS "Status" FROM "' + PREFIX + 'PasswordResetLogs" prl INNER JOIN "' + PREFIX + 'Customers" c ON c."Id" = prl."CustomerId" WHERE prl."Token" = $1 AND prl."TokenExpireDate" > $2', [resetToken, new Date()]);

    const passwordResetLog = result.rows[0];
    const passwordRegex = /^(?=.*[a-zçğıöşü])(?=.*[A-ZÇĞİÖŞÜ])(?=.*[@$!%*?&.,;:])[A-Za-zçÇğĞıİöÖşŞüÜ\d@$!%*?&.,;:]{8,}$/;
    const hashedPassword = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);

    if (!passwordResetLog) {
      return res.status(400).json({ message: 'Geçersiz token.' });
    }

    if (!password || !passwordRegex.test(password)) {
      return res.status(400).json({ message: 'Şifrenizi geçerli formatta giriniz.' });
    }

    if (password != confirmPassword) {
      return res.status(400).json({ message: 'Şifreler eşleşmiyor.' });
    }

    if (hashedPassword === passwordResetLog.OldHashedPassword) {
      return res.status(400).json({ message: 'Şifreniz bir önceki şifreniz ile aynı olamaz.' });
    }

    if (passwordResetLog.Status != 'Active') {
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
                    <Id/>
                    <CustomerId>${passwordResetLog.CustomerId}</CustomerId>
                    <EmailAddress></EmailAddress>
                    <Token></Token>
                    <TokenExpireDate></TokenExpireDate>
                    <HashedPassword>${hashedPassword}</HashedPassword>
                    <UpdateDate></UpdateDate>
                </ResetPassword>
              </PasswordManagement>`,
        testMode: false,
        culture: null
      });

    } catch (error) {
      res.status(500).json({ message: 'Şifre sıfırlama başarısız.', error: error.response.data });
    }

    res.status(200).json({ message: 'Şifreniz başarılı şekilde sıfırlandı.' });
  } catch (err) {
    res.status(500).json({ message: 'Şifre sıfırlama başarısız', error: err.message });
  }
});

// Mint token endpointi
app.post('/token-operation', authMiddleware, async (req, res) => {
  const { assetType, operationType, assetAmount, unitPrice } = req.body;

  try {
    const customerId = req.user?.customerId;

    const resultTL = await pool.query(`SELECT "Amount" FROM "rcoretestTokBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, "TL"]);
    const balanceTL = resultTL.rows[0].Amount;

    const resultMTLK = await pool.query(`SELECT "Amount" FROM "rcoretestTokBalances" WHERE "CustomerId" = $1 AND "Type" = $2`, [customerId, assetType]);
    const balanceMTLK = resultMTLK.rows[0].Amount;

    const contributionMargin = 10;
    const fee = 0.002;
    const totalAmount = (assetAmount * unitPrice * (1 + fee) + contributionMargin).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 }); //10*101 = 1010

    if (operationType == 1 && totalAmount > balanceTL) { //MİNT 
      res.status(400).json({ message: "Hesap bakiyesi yeterli değil." });
    }

    if (operationType == 2 && assetAmount > balanceMTLK) { //BURN
      res.status(400).json({ message: "Hesap bakiyesi yeterli değil." });
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
                  <WalletInformation>
                    <TaurusWalletId/>
                  </WalletInformation>
                  <BalanceInformation>
                    <AssetType>${assetType}</AssetType>
                    <OperationType>${operationType}</OperationType>
                    <AssetAmount>${assetAmount}</AssetAmount>
                    <UnitPrice>${unitPrice}</UnitPrice>
                    <ContributionMargin>${contributionMargin}</ContributionMargin>
                    <Fee>${fee}</Fee>
                    <Type/>
                    <TotalAmount>${totalAmount}</TotalAmount>
                  </BalanceInformation>
                </AssetOperationManagement>`,
        culture: null
      });

    } catch (error) {
      res.status(500).json({ message: 'İşlem emri iletimi başarısız!', hata: error.response.data });
    }

    res.status(200).json({ message: 'İşlem emri başarılı şekilde oluşturuldu.' });
  } catch (err) {
    res.status(500).json({ message: 'İşlem emri oluşturulamadı!', hata: err.message });
  }

});

// Calculate endpointi
app.post("/calculate", authMiddleware, async (req, res) => {
  const { toType, fromType, amount } = req.body;

  try {
    const resultUnitPrice = await pool.query(`SELECT "UnitPrice" FROM "rcoretestTokAssets" WHERE "Type" = 'MTLK' `);
    const unitPrice = resultUnitPrice.rows[0].UnitPrice;
    var result, reCalculatedAmount, fee, contributionMargin = 0

    if (amount <= 0) {
      res.status(400).json({ message: 'Hatalı tutar girdiniz!' })
    }

    if (toType == "MTLK" && fromType == "TL") {

      reCalculatedAmount = (amount - 10) / 1.002 / unitPrice; // (1000*0.998 - 10 )/ 101 = 9,78
      reCalculatedAmount = Math.floor(reCalculatedAmount);

      fee = ((reCalculatedAmount * unitPrice) * 0.002).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
      contributionMargin = (10).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

      if (amount < (unitPrice * (1.002) + 10)) {
        return res.status(400).json({ message: 'Yetersiz Bakiye!' })
      }

      result = ((reCalculatedAmount * unitPrice) * (1.002) + 10).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 }); // (9 * 101)1.002 + 10
      return res.status(200).json({ totalAmount: result, fee: fee, contributionMargin: contributionMargin, reCalculatedAmount: reCalculatedAmount, fromUnitPrice: unitPrice });

    } else if (toType == "TL" && fromType == "MTLK") {

      if (!isInt(amount)){
        return res.status(400).json({ message: 'Hatalı tutar girdiniz!' });
      }

      function isInt(value) {
        return !isNaN(value) && 
               parseInt(Number(value)) == value && 
               !isNaN(parseInt(value, 10));
      }

      result = ((amount * unitPrice) * 1.002 + 10).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
      fee = (amount * unitPrice * 0.002).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });
      contributionMargin = (10).toLocaleString('tr-TR', { maximumFractionDigits: 2, minimumFractionDigits: 2 });

      return res.status(200).json({ totalAmount: result, fee: fee, contributionMargin: contributionMargin, reCalculatedAmount: amount, fromUnitPrice: unitPrice });

    } else {
      return res.status(400).json({ message: 'Geçersiz varlık tipi.' })
    }


  } catch (error) {
    return res.status(500).json({ message: "Tutar hesaplanamadı!", hata: error.message })
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
    data: `<CustomerOnboarding><IdentityNumber>${identityNumber}</IdentityNumber><Name>${name}</Name><Surname>${surname}</Surname><BirthDate>${birthDate}</BirthDate><EmailAddress>${email}</EmailAddress><PhoneNumber>${phoneNumber}</PhoneNumber><Password>${password}</Password></CustomerOnboarding>`,
    culture: null
  });
};

const triggerProcess = async (emailVerificationStatus, email) => {

  return axios.post('http://emakin-web.tokenization.svc.cluster.local:80/rest/v1/trigger', {
    apiKey: "4a73969d-c4d1-4908-9a3d-6b080b2e05fe",
    logonId: "support@bt.guru",
    logonProvider: "Organization",
    eventName: "Verify2FACode." + email,
    inputData: "<CustomerOnboarding><EmailVerificationStatus>" + emailVerificationStatus + "</EmailVerificationStatus></CustomerOnboarding>",
    testMode: false,
    culture: null
  });
};

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servis ayağa kalktı, PORT:${PORT}`);
});


