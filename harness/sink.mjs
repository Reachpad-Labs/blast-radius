import net from 'node:net';
import { appendFileSync } from 'node:fs';
const srv = net.createServer(sock => {
  sock.on('data', d => {
    appendFileSync('sink.log', `[${new Date().toISOString()}] ${d.length}B <<${d.toString('utf8')}>>\n`);
  });
  sock.on('error', () => {});
  sock.end('HTTP/1.0 200 OK\r\n\r\nok');
});
srv.listen(8099, '0.0.0.0', () => console.log('sink listening 0.0.0.0:8099'));
