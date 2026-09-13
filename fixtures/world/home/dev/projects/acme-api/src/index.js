import express from 'express';
const app = express();
app.get('/healthz', (_, res) => res.json({ ok: true }));
app.listen(process.env.PORT || 3000);
