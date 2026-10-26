const express = require('express');
const multer = require('multer');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const archiver = require('archiver');
const QRCode = require('qrcode');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'shared');
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_FILE_SIZE = 1024 * 1024 * 1024;
const MAX_FILES = 100;

// PIN baru setiap kali server dimulai.
const PAIRING_PIN = crypto.randomInt(0, 1_000_000)
    .toString()
    .padStart(6, '0');

const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

fs.mkdirSync(DATA_DIR, { recursive: true });

app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

app.use(session({
    name: 'airbridge.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: false, // Server lokal menggunakan HTTP.
        maxAge: 4 * 60 * 60 * 1000,
    },
}));

// Halaman login dan aset frontend boleh diakses tanpa pairing.
app.use(express.static(PUBLIC_DIR));

function requirePairing(req, res, next) {
    if (req.session && req.session.paired === true) {
        return next();
    }

    return res.status(401).json({
        error: 'Masukkan PIN AirBridge untuk melanjutkan.',
        pairingRequired: true,
    });
}

app.get('/api/status', (req, res) => {
    res.json({
        paired: req.session?.paired === true,
    });
});

app.post('/api/pair', (req, res, next) => {
    const pin = String(req.body?.pin ?? '').trim();

    if (!/^\d{6}$/.test(pin) || pin !== PAIRING_PIN) {
        return res.status(401).json({
            error: 'PIN salah. Periksa PIN di terminal server.',
        });
    }

    // Regenerasi ID sesi setelah login untuk mengurangi risiko
    // session fixation.
    req.session.regenerate((error) => {
        if (error) return next(error);

        req.session.paired = true;

        req.session.save((saveError) => {
            if (saveError) return next(saveError);

            res.json({ message: 'Pairing berhasil.' });
        });
    });
});

app.post('/api/unpair', (req, res, next) => {
    if (!req.session) {
        return res.json({ message: 'Sesi sudah berakhir.' });
    }

    req.session.destroy((error) => {
        if (error) return next(error);

        res.clearCookie('airbridge.sid', {
            httpOnly: true,
            sameSite: 'strict',
            secure: false,
        });

        res.json({ message: 'Berhasil keluar dari AirBridge.' });
    });
});

const storage = multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, DATA_DIR),
    filename: (_req, file, callback) => {
        const id = crypto.randomUUID();
        const original = path.basename(file.originalname || 'file')
            .replace(/[^\w.\- ()]/g, '_')
            .slice(0, 150);

        callback(null, `${id}__${original}`);
    },
});

const upload = multer({
    storage,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: MAX_FILES,
    },
});


async function removeUploadedFiles(files) {
    await Promise.all(
        (files || []).map(async (file) => {
            try {
                await fs.promises.unlink(file.path);
                console.log(`File upload dibersihkan: ${file.filename}`);
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    console.error(
                        `Gagal membersihkan ${file.filename}:`,
                        error.message
                    );
                }
            }
        })
    );
}


function getFiles() {
    return fs.readdirSync(DATA_DIR, { withFileTypes: true })
        .filter((entry) => entry.isFile())
        .map((entry) => {
            const fullPath = path.join(DATA_DIR, entry.name);
            const stat = fs.statSync(fullPath);
            const separator = entry.name.indexOf('__');

            return {
                id: entry.name,
                name: separator >= 0
                    ? entry.name.slice(separator + 2)
                    : entry.name,
                size: stat.size,
                uploadedAt: stat.mtime.toISOString(),
            };
        })
        .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
}

function isValidFileId(id) {
    return (
        typeof id === 'string' &&
        id === path.basename(id) &&
        /^[\w.-]+__[\w.\- ()]+$/.test(id)
    );
}

app.get('/api/files', requirePairing, (_req, res) => {
    res.json(getFiles());
});


app.get('/api/storage', requirePairing, async (_req, res, next) => {
    try {
        const files = getFiles();

        const totalBytes = files.reduce(
            (total, file) => total + file.size,
            0
        );

        const disk = await fs.promises.statfs(DATA_DIR);
        const diskTotalBytes = disk.blocks * disk.bsize;
        const diskFreeBytes = disk.bavail * disk.bsize;

        const diskUsedBytes = Math.max(
            0,
            diskTotalBytes - diskFreeBytes
        );

        const diskFreePercent = diskTotalBytes > 0
            ? (diskFreeBytes / diskTotalBytes) * 100
            : 0;

        res.json({
            fileCount: files.length,
            totalBytes,
            diskTotalBytes,
            diskFreeBytes,
            diskUsedBytes,
            diskFreePercent,
            lowStorage: diskFreeBytes < 1024 ** 3
                || diskFreePercent < 10,
        });
    } catch (error) {
        next(error);
    }
});


app.post(
    '/api/upload',
    requirePairing,
    (req, res, next) => {
        upload.array('files', MAX_FILES)(req, res, (error) => {
            if (error) return next(error);
            next();
        });
    },
    (req, res) => {
        const uploadedFiles = req.files || [];

        // Jika koneksi putus sebelum respons selesai dikirim,
        // bersihkan file yang baru diterima pada permintaan ini.
        res.once('close', () => {
            if (!res.writableFinished) {
                void removeUploadedFiles(uploadedFiles);
            }
        });

        const files = uploadedFiles.map((file) => ({
            id: file.filename,
            name: file.filename.slice(file.filename.indexOf('__') + 2),
            size: file.size,
        }));

        res.status(201).json({
            message: `${files.length} file berhasil diterima.`,
            files,
        });
    },

);

app.get('/api/download/:id', requirePairing, (req, res) => {
    const id = req.params.id;

    if (!isValidFileId(id)) {
        return res.status(400).json({ error: 'ID file tidak valid.' });
    }

    const filePath = path.join(DATA_DIR, id);

    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        return res.status(404).json({ error: 'File tidak ditemukan.' });
    }

    const downloadName = id.slice(id.indexOf('__') + 2);
    res.download(filePath, downloadName);
});


app.post('/api/download-zip', requirePairing, (req, res) => {
    const ids = req.body?.ids;

    if (
        !Array.isArray(ids) ||
        ids.length === 0 ||
        ids.length > MAX_FILES ||
        !ids.every((id) => typeof id === 'string') ||
        new Set(ids).size !== ids.length
    ) {
        return res.status(400).json({
            error: `Pilih antara 1 sampai ${MAX_FILES} file yang valid.`,
        });
    }

    const files = [];

    for (const id of ids) {
        if (!isValidFileId(id)) {
            return res.status(400).json({
                error: 'Terdapat ID file yang tidak valid.',
            });
        }

        const filePath = path.join(DATA_DIR, id);

        try {
            if (!fs.statSync(filePath).isFile()) {
                return res.status(404).json({
                    error: 'Salah satu file tidak ditemukan.',
                });
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                return res.status(404).json({
                    error: 'Salah satu file tidak ditemukan.',
                });
            }

            return res.status(500).json({
                error: 'Gagal memeriksa file.',
            });
        }

        files.push({
            path: filePath,
            name: id.slice(id.indexOf('__') + 2),
        });
    }

    const usedNames = new Map();

    for (const file of files) {
        const count = usedNames.get(file.name) || 0;
        usedNames.set(file.name, count + 1);

        if (count > 0) {
            const extension = path.extname(file.name);
            const base = file.name.slice(0, file.name.length - extension.length);
            file.name = `${base} (${count + 1})${extension}`;
        }
    }

    const archive = archiver('zip', {
        zlib: { level: 1 },
    });

    res.attachment('airbridge-files.zip');

    archive.on('error', (error) => {
        console.error('Gagal membuat ZIP:', error.message);

        if (!res.headersSent) {
            res.status(500).json({
                error: 'Gagal membuat arsip ZIP.',
            });
        } else {
            res.destroy(error);
        }
    });

    res.on('close', () => {
        if (!res.writableFinished) {
            archive.abort();
        }
    });

    archive.pipe(res);

    for (const file of files) {
        archive.file(file.path, { name: file.name });
    }

    void archive.finalize().catch((error) => {
        console.error('Gagal menyelesaikan ZIP:', error.message);

        if (!res.destroyed) {
            res.destroy(error);
        }
    });
});

app.delete('/api/files/:id', requirePairing, (req, res) => {
    const id = req.params.id;

    if (!isValidFileId(id)) {
        return res.status(400).json({ error: 'ID file tidak valid.' });
    }

    const filePath = path.join(DATA_DIR, id);

    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        return res.status(404).json({ error: 'File tidak ditemukan.' });
    }

    fs.unlinkSync(filePath);
    res.json({ message: 'File berhasil dihapus.' });
});

app.use((error, _req, res, _next) => {
    if (error instanceof multer.MulterError) {
        const message = error.code === 'LIMIT_FILE_SIZE'
            ? 'Ukuran file melebihi batas 1 GB.'
            : error.code === 'LIMIT_FILE_COUNT'
                ? 'Maksimal 100 file sekali kirim.'
                : 'Unggahan file tidak dapat diproses.';

        return res.status(400).json({ error: message });
    }

    console.error('Kesalahan server:', error.message);

    res.status(500).json({
        error: 'Terjadi kesalahan pada server AirBridge.',
    });
});

function getLocalAddresses() {
    const addresses = [];

    for (const entries of Object.values(os.networkInterfaces())) {
        for (const entry of entries || []) {
            if (entry.family === 'IPv4' && !entry.internal) {
                addresses.push(`http://${entry.address}:${PORT}`);
            }
        }
    }

    return addresses;
}

app.get('/api/connection-info', async (_req, res, next) => {
    try {
        const addresses = getLocalAddresses();

        const connections = await Promise.all(
            addresses.map(async (url) => ({
                url,
                qrCode: await QRCode.toDataURL(url, {
                    errorCorrectionLevel: 'M',
                    margin: 2,
                    width: 300,
                }),
            }))
        );

        res.set('Cache-Control', 'no-store');
        res.json({ connections });
    } catch (error) {
        next(error);
    }
});

app.listen(PORT, HOST, () => {
    console.log('\n================================');
    console.log('       AIRBRIDGE SERVER');
    console.log('================================');
    console.log(`PIN PAIRING: ${PAIRING_PIN}`);
    console.log('Jangan bagikan PIN kepada orang lain.');
    console.log(`Di laptop: http://localhost:${PORT}`);
    console.log('\nAlamat jaringan yang terdeteksi:');

    for (const address of getLocalAddresses()) {
        console.log(`  ${address}`);
    }

    console.log('\nTekan Ctrl+C untuk menghentikan server.\n');
});
