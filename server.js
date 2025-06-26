const express = require('express');
const multer = require('multer');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));

const upload = multer({ dest: 'uploads/' });

// Conversão de KM para bytes (valor + complemento)
function convertMileageToEepromBytes(km) {
    const factor = 0.031;
    const valor = Math.floor(km * factor);
    const complemento = 0xFFFF - valor;

    const buf = Buffer.alloc(4);
    buf.writeUInt16LE(valor, 0);
    buf.writeUInt16LE(complemento, 2);
    return buf;
}

// Offsets da Titan 160
const mileageLocationsTitan = [
    0x98, 0x9C, 0xA0, 0xA4, 0xA8, 0xAC,
    0xB0, 0xB4, 0xB8, 0xBC, 0xC0, 0xC4,
    0xC8, 0xCC, 0xD0, 0xD4, 0xD8,
    0xDA, 0xDE, 0xE0, 0xE2
];

// Offsets da Biz 2018
const mileageLocationsBiz = [
    0x005C, 0x0060, 0x0064, 0x0068, 0x006C,
    0x0070, 0x0074, 0x0078, 0x007C, 0x0080,
    0x0084, 0x0088, 0x008C, 0x0098
];

// Offsets da CB 500X 2023
const mileageLocationsCb500x2023 = [
    0x0100, 0x0104, 0x0108, 0x010C,
    0x0110, 0x0114, 0x0118, 0x011C,
    0x0120, 0x0124, 0x0128, 0x012C,
    0x0130, 0x0134, 0x0138, 0x013C
];

// Função para obter configuração por modelo
function getModelConfig(modelo) {
    if (modelo === 'titan160') {
        return {
            template: 'titan160.bin',
            offsets: mileageLocationsTitan
        };
    } else if (modelo === 'biz2018') {
        return {
            template: 'biz2018.bin',
            offsets: mileageLocationsBiz
        };
    } else if (modelo === 'cb500x2023') {
        return {
            template: 'cb500x2023.bin',
            offsets: mileageLocationsCb500x2023
        };
    } else {
        throw new Error('Modelo inválido');
    }
}

// Geração de arquivo BIN com nova quilometragem
app.post('/alterar-e-baixar-template', async (req, res) => {
    try {
        const { new_mileage, model } = req.body;
        const km = parseInt(new_mileage);
        if (isNaN(km) || km < 0) return res.status(400).send('KM inválido');

        const { template, offsets } = getModelConfig(model);
        const filePath = path.join(__dirname, 'data', template);
        const original = await fs.readFile(filePath);
        const buffer = Buffer.from(original);

        const kmBytes = convertMileageToEepromBytes(km);
        for (const offset of offsets) {
            if (offset + 4 <= buffer.length) {
                kmBytes.copy(buffer, offset);
            }
        }

        res.setHeader('Content-Disposition', `attachment; filename="${model}_${km}km.bin"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(buffer);
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro interno');
    }
});

// Leitura de KM com detecção automática de modelo
app.post('/ler-km', upload.single('arquivo_bin'), async (req, res) => {
    try {
        const filePath = req.file.path;
        const bin = await fs.readFile(filePath);

        const modelos = [
            { nome: 'titan160', offsets: mileageLocationsTitan },
            { nome: 'biz2018', offsets: mileageLocationsBiz },
            { nome: 'cb500x2023', offsets: mileageLocationsCb500x2023 }
        ];

        let melhorModelo = null;
        let maiorContagem = 0;
        let melhorValor = 0;

        for (const { nome, offsets } of modelos) {
            const valoresValidos = [];

            for (const offset of offsets) {
                if (offset + 4 <= bin.length) {
                    const valor = bin.readUInt16LE(offset);
                    const complemento = bin.readUInt16LE(offset + 2);
                    if ((valor + complemento) === 0xFFFF) {
                        valoresValidos.push(valor);
                    }
                }
            }

            if (valoresValidos.length > maiorContagem) {
                const frequencias = {};
                for (const v of valoresValidos) {
                    frequencias[v] = (frequencias[v] || 0) + 1;
                }
                const valorMaisFrequente = Object.entries(frequencias).sort((a, b) => b[1] - a[1])[0][0];

                melhorModelo = nome;
                melhorValor = valorMaisFrequente;
                maiorContagem = valoresValidos.length;
            }
        }

        if (!melhorModelo) {
            return res.status(400).send('Não foi possível identificar o KM.');
        }

        const km = Math.round(melhorValor / 0.031);
        res.json({ modelo: melhorModelo, km });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao ler arquivo');
    }
});

// Iniciar servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
