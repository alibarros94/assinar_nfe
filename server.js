const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');

const app = express();
app.use(bodyParser.json({ limit: '2mb' }));

app.post('/sign', (req, res) => {
  const { xml, tag } = req.body;

  try {
    const privateKey = fs.readFileSync('./cert/private.pem', 'utf-8');
    const certificate = fs.readFileSync('./cert/cert.pem', 'utf-8');

    const sig = new SignedXml();
    sig.addReference(
      `//*[local-name(.)='${tag}']`,
      ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
      'http://www.w3.org/2000/09/xmldsig#sha1'
    );

    sig.signingKey = privateKey;
    sig.keyInfoProvider = {
      getKeyInfo: () => `<X509Data></X509Data>`
    };

    sig.computeSignature(xml);

    res.json({ signedXml: sig.getSignedXml() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, () => console.log('🚀 API de assinatura rodando na porta 3000'));
