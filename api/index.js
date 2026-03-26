import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-key');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    res.setHeader('Content-Type', 'application/json');

    const action      = req.method === 'POST' ? req.body?.action     : req.query?.action;
    const device_id   = req.method === 'POST' ? req.body?.device_id  : req.query?.device_id;
    const install_time = req.body?.install_time ?? null;

    if (!device_id && action !== 'admin_list') {
        return res.status(400).json({ status: 'error', msg: 'missing device_id' });
    }

    try {
        if (action === 'register') {
            await sql`
                INSERT INTO users (device_id, install_time)
                VALUES (${device_id}, ${install_time})
                ON CONFLICT (device_id) DO NOTHING
            `;
            const rows = await sql`
                SELECT is_banned, ban_reason FROM users WHERE device_id = ${device_id}
            `;
            const user = rows[0];
            return res.json({
                status:     'ok',
                is_banned:  user.is_banned,
                ban_reason: user.ban_reason ?? ''
            });

        } else if (action === 'check') {
            const rows = await sql`
                SELECT is_banned, ban_reason FROM users WHERE device_id = ${device_id}
            `;
            if (rows.length === 0) {
                return res.json({ status: 'not_found' });
            }
            const user = rows[0];
            return res.json({
                status:     'ok',
                is_banned:  user.is_banned,
                ban_reason: user.ban_reason ?? ''
            });

        } else if (action === 'admin_list') {
            const key = req.headers['x-admin-key'];
            if (key !== process.env.ADMIN_KEY) {
                return res.status(403).json({ status: 'forbidden' });
            }
            const rows = await sql`SELECT * FROM users ORDER BY first_seen DESC`;
            return res.json({ status: 'ok', users: rows });

        } else if (action === 'ban' || action === 'unban') {
            const key = req.headers['x-admin-key'];
            if (key !== process.env.ADMIN_KEY) {
                return res.status(403).json({ status: 'forbidden' });
            }
            const reason = req.body?.reason ?? null;
            if (action === 'ban') {
                await sql`UPDATE users SET is_banned=true, ban_reason=${reason} WHERE device_id=${device_id}`;
            } else {
                await sql`UPDATE users SET is_banned=false, ban_reason=null WHERE device_id=${device_id}`;
            }
            return res.json({ status: 'ok' });

        } else {
            return res.status(400).json({ status: 'error', msg: 'unknown action' });
        }

    } catch (e) {
        return res.status(500).json({ status: 'error', msg: e.message });
    }
}
