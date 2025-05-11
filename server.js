const express = require('express');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json({ limit: '10mb' }));

app.post('/sign', (req, res) => {
  try {
    const { xml, tag, cert, key } = req.body;

    if (!xml || !tag || !cert || !key) {
      return res.status(400).json({ error: 'Missing xml, tag, cert, or key' });
    }

    const sig = new SignedXml();
    sig.addReference(`//*[local-name(.)='${tag}']`);
    sig.signingKey = key;
    sig.keyInfoProvider = {
      getKeyInfo: () => `<X509Data></X509Data>`,
      getKey: () => cert
    };

    sig.computeSignature(xml);

    return res.send(sig.getSignedXml());
  } catch (e) {
    return res.status(500).json({ error: 'Signature failed', detail: e.message });
  }
});

app.listen(3000, () => console.log('Ready on port 3000'));
