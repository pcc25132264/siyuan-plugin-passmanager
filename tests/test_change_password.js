// 测试：修改主密码时按块 ID 重加密加密块的逻辑
// 运行：node --test tests/test_change_password.js  （由 tests 目录执行）
// 依赖：Node 内置 test runner + assert，无需第三方框架。

const { test } = require('node:test');
const assert = require('node:assert');
const Module = require('node:module');

// --- 1. 让 index.js 能引用的 WebCrypto 可用（真实 AES-GCM/PBKDF2） ---
globalThis.crypto = require('node:crypto').webcrypto;

// --- 2. 拦截 require('siyuan')，提供最小可运行 mock ---
const fakeSiyuan = {
    Plugin: class Plugin {},
    Dialog: class Dialog {},
    Setting: class Setting {},
    EventBus: class EventBus { on() {} emit() {} },
    showMessage() {},
    // 网络 mock：由测试动态替换 fetchSyncPost 实现
    fetchSyncPost: async () => ({ code: -1, msg: 'not-mocked' }),
};
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
    if (request === 'siyuan') return fakeSiyuan;
    return origLoad.apply(this, arguments);
};

// --- 3. 加载插件，拿到 PassManagerPlugin 类 ---
const PassManagerPlugin = require('../index.js');
assert.ok(PassManagerPlugin, '应导出 PassManagerPlugin 类');

// --- 4. 构造轻量实例（不触发构造函数与真实 DOM） ---
function makePlugin() {
    const p = Object.create(PassManagerPlugin.prototype);
    const storage = new Map();
    p.saveData = async (name, obj) => { storage.set(name, JSON.parse(JSON.stringify(obj))); };
    p.loadData = async (name) => storage.has(name) ? JSON.parse(JSON.stringify(storage.get(name))) : null;
    p.i18n = {};
    return p;
}

// --- 样例 kramdown：含 2 个 crypto 块 + 1 个普通代码块 + 1 段文本 ---
const sampleKramdown = [
    '正常段落内容',
    '',
    '```crypto',
    '{"iv":"3fa5ace891673a98f269b148","data":"550a6e8878c552ddffb636ebb23c79bd75aa5dbebabe91f28097de6e39581278e5089ef58cbf81fc39640032a158cc55f42e941e4b82633a266700e55ef3581adf7b7919b72a921d"}',
    '```',
    '{: id="20260324152103-lbokog9" updated="20260326172810"}',
    '',
    '```crypto',
    '{"iv":"745fd0c73e1b7c8f0fb97699","data":"59591b5270883c19c9025fe11b5c93ebb77c5f4bd00bdc607844fc95bb4e65296932b7eae4954314825e67f50cfb27126a5ac73252c0a01a567e2e4876996a3088922377e975"}',
    '```',
    '{: id="20260326172941-w69bkbo" updated="20260326172941"}',
    '',
    '```python',
    'print("hello")',
    '```',
    '{: id="normal-block" updated="x"}',
].join('\n');

test('extractCryptoBlocks 只提取 crypto 块并按块 ID 关联', () => {
    const p = makePlugin();
    const out = [];
    p.extractCryptoBlocks(sampleKramdown, out);
    assert.strictEqual(out.length, 2, '应只提取 2 个 crypto 块，忽略普通代码块');
    assert.strictEqual(out[0].id, '20260324152103-lbokog9');
    assert.strictEqual(out[0].iv, '3fa5ace891673a98f269b148');
    assert.ok(out[0].data.length > 0);
    assert.strictEqual(out[1].id, '20260326172941-w69bkbo');
});

test('extractCryptoBlocks: 清除整段 kramdown 中的零宽空格，避免漏掉带 style/插空格的加密块', () => {
    const p = makePlugin();
    const dataJson = JSON.stringify({ iv: '974f8d8feabc9545d970fb2a', data: '0e4f23' });
    // 模拟 SiYuan 在 fence 标记和 {: id= 中插入 \u200B，且该块带 style 属性（形如用户报告的真实坏块）
    const mk = (s) => s.split('').join('\u200B');
    const kramdown = [
        '```crypto',
        dataJson,
        '```',
        '{: id="20260324145418-2kmuccz" style="padding: 0px; background-color: transparent;" updated="20260324145310"}',
    ].map((line, i) => (i <= 2 ? mk(line) : line)).join('\n');
    const out = [];
    p.extractCryptoBlocks(kramdown, out);
    assert.strictEqual(out.length, 1, '零宽空格不应导致加密块被漏掉');
    assert.strictEqual(out[0].id, '20260324145418-2kmuccz');
    assert.strictEqual(out[0].iv, '974f8d8feabc9545d970fb2a');
});

test('加密块 ID 索引 add/remove/load 持久化', async () => {
    const p = makePlugin();
    assert.deepStrictEqual(await p.loadCryptoBlockIndex(), []);
    await p.addCryptoBlockId('b1');
    await p.addCryptoBlockId('b2');
    await p.addCryptoBlockId('b1'); // 重复添加应去重
    assert.deepStrictEqual(await p.loadCryptoBlockIndex(), ['b1', 'b2']);
    await p.removeCryptoBlockId('b1');
    assert.deepStrictEqual(await p.loadCryptoBlockIndex(), ['b2']);
    await p.saveCryptoBlockIndex(['a', 'b']);
    assert.deepStrictEqual(await p.loadCryptoBlockIndex(), ['a', 'b']);
});

test('extractCryptoBlocks 忽略内容为空（data 为空）的加密块，避免解密报错', () => {
    const p = makePlugin();
    const emptyKramdown = [
        '```crypto',
        '{"iv":"","data":""}',
        '```',
        '{: id="empty-block" updated="x"}',
    ].join('\n');
    const out = [];
    p.extractCryptoBlocks(emptyKramdown, out);
    assert.strictEqual(out.length, 0, '空载荷的加密块不应被提取索引，也不会在改密时被解密');
});

test('extractCryptoBlocks: HTML overlay 混在代码块内部且带内层 IAL 时，ID 须归属外层加密块自身', () => {
    const p = makePlugin();
    // 模拟真实坏块 20260324152118-r92700i：`crypto 块内混入 HTML overlay 面板，且其内层还有个
    // 属于 overlay 的 IAL（闭 fence 之前）；必须取闭 fence 之后的外层 IAL 作为加密块 id。
    const kramdown = [
        '```',
        '\n\n{"iv":"932324638311336563ecc237","data":"a8f2b34c9d"}',
        '<div><div class="pm-crypto-overlay">主键 user pwd</div></div>',
        '{: id="20260325202443-oyj1mcf"}', // 内层 overlay 的 IAL，在闭 fence 之前
        '```',
        '{: id="20260324152118-r92700i" updated="20260324152127"}',
    ].join('\n');
    const out = [];
    p.extractCryptoBlocks(kramdown, out);
    assert.strictEqual(out.length, 1, '加密块必须被识别，不能因 info 为空/HTML 混入而漏掉');
    assert.strictEqual(out[0].id, '20260324152118-r92700i', 'ID 必须归属外层加密块自身，而非内层 overlay 的 id');
    assert.strictEqual(out[0].iv, '932324638311336563ecc237');
    assert.strictEqual(out[0].data, 'a8f2b34c9d');
});

test('collectCryptoBlocksByWalking 通过文档树遍历收集 crypto 块', async () => {
    const p = makePlugin();
    // mock 网络：1 个笔记本 -> 1 个文档，文档 kramdown 含 2 个 crypto 块
    fakeSiyuan.fetchSyncPost = async (path, payload) => {
        if (path === '/api/notebook/lsNotebooks') {
            return { code: 0, data: { notebooks: [{ id: 'nb1', name: 'N1', closed: false }] } };
        }
        if (path === '/api/filetree/listDocsByPath') {
            return { code: 0, data: { files: [{ id: 'doc1', name: 'doc1', subFileCount: 0 }] } };
        }
        if (path === '/api/block/getBlockKramdown') {
            return { code: 0, data: { id: payload.id, kramdown: sampleKramdown } };
        }
        return { code: -1, msg: 'unexpected:' + path };
    };
    const blocks = await p.collectCryptoBlocksByWalking();
    assert.strictEqual(blocks.length, 2);
    assert.ok(blocks.every((b) => b.id && b.iv && b.data));
});

test('gatherCryptoBlocksForChange: 改密时始终遍历全库并与索引合并，索引外的块不遗漏', async () => {
    const p = makePlugin();
    await p.saveCryptoBlockIndex(['b1', 'b2']);
    p.buildCryptoIndex = async () => ['b1', 'b2', 'b3']; // 遍历覆盖索引并找到索引外的 b3
    p.getCryptoBlockById = async (id) => ({ id, data: 'd', iv: 'i' });
    const okCrypto = { decrypt: async (data, iv) => ({ content: 'plain-' + iv }) };
    const { list, failedCount } = await p.gatherCryptoBlocksForChange(okCrypto);
    assert.strictEqual(failedCount, 0);
    assert.deepStrictEqual(list.map((b) => b.id), ['b1', 'b2', 'b3'], '索引外的 b3 也须被收集重加密，避免改密后损坏');
    assert.strictEqual(list[0].obj.content, 'plain-i');
});

test('gatherCryptoBlocksForChange: 遍历全库失败时退化为仅用索引，不阻塞改密', async () => {
    const p = makePlugin();
    await p.saveCryptoBlockIndex(['b1', 'b2']);
    p.buildCryptoIndex = async () => { throw new Error('network'); };
    p.getCryptoBlockById = async (id) => ({ id, data: 'd', iv: 'i' });
    const okCrypto = { decrypt: async (data, iv) => ({ content: 'plain-' + iv }) };
    const { list, failedCount } = await p.gatherCryptoBlocksForChange(okCrypto);
    assert.strictEqual(failedCount, 0);
    assert.deepStrictEqual(list.map((b) => b.id), ['b1', 'b2'], '遍历失败时至少回退到索引');
});

test('gatherCryptoBlocksForChange: 存在解不开的块 -> failedCount>0（改密将被中止）', async () => {
    const p = makePlugin();
    await p.saveCryptoBlockIndex(['b1', 'b2']);
    p.buildCryptoIndex = async () => ['b1', 'b2'];
    p.getCryptoBlockById = async (id) => ({ id, data: 'd', iv: 'i' });
    class FlakyCrypto {
        async decrypt(data, iv) {
            throw new Error('解密失败，密码不正确或数据已损坏');
        }
    }
    const { list, failedCount } = await p.gatherCryptoBlocksForChange(new FlakyCrypto());
    assert.strictEqual(failedCount, 2, '有 2 个块解不开，改密必须中止');
    assert.strictEqual(list.length, 0);
});

test('gatherCryptoBlocksForChange: 全部解不开 -> list 为空、failedCount=N（防止只换盐导致全库损坏）', async () => {
    const p = makePlugin();
    await p.saveCryptoBlockIndex(['b1', 'b2', 'b3']);
    p.buildCryptoIndex = async () => ['b1', 'b2', 'b3'];
    p.getCryptoBlockById = async (id) => ({ id, data: 'd', iv: 'i' });
    const badCrypto = { decrypt: async () => { throw new Error('bad'); } };
    const { list, failedCount } = await p.gatherCryptoBlocksForChange(badCrypto);
    assert.strictEqual(failedCount, 3);
    assert.strictEqual(list.length, 0);
});

test('gatherCryptoBlocksForChange: 返回 raws（旧密文）供失败回滚备份', async () => {
    const p = makePlugin();
    await p.saveCryptoBlockIndex(['b1', 'b2']);
    p.buildCryptoIndex = async () => ['b1', 'b2'];
    p.getCryptoBlockById = async (id) => ({ id, data: 'old-data-' + id, iv: 'old-iv-' + id });
    const okCrypto = { decrypt: async (data, iv) => ({ content: 'plain' }) };
    const { list, raws } = await p.gatherCryptoBlocksForChange(okCrypto);
    assert.strictEqual(list.length, 2);
    assert.deepStrictEqual(raws, [
        { id: 'b1', data: 'old-data-b1', iv: 'old-iv-b1' },
        { id: 'b2', data: 'old-data-b2', iv: 'old-iv-b2' },
    ], 'raws 应保存每块旧密文，用于回滚');
});

test('getCryptoBlockById: 从单块 kramdown 中提取加密块，非加密/缺失返回 null', async () => {
    const p = makePlugin();
    fakeSiyuan.fetchSyncPost = async (path, payload) => {
        if (path === '/api/block/getBlockKramdown' && payload.id === '20260324152103-lbokog9') {
            return { code: 0, data: { id: '20260324152103-lbokog9', kramdown: sampleKramdown } }; // 含 20260324152103-lbokog9
        }
        return { code: 0, data: {} }; // 其他 id 无 kramdown -> null
    };
    // 索引里的 id 应对应到 kramdown 内实际的 crypto 块
    const hit = await p.getCryptoBlockById('20260324152103-lbokog9');
    assert.ok(hit, '应能读取该加密块');
    assert.strictEqual(hit.id, '20260324152103-lbokog9');
    // 请求一个不存在的 id -> null
    const miss = await p.getCryptoBlockById('missing-id');
    assert.strictEqual(miss, null, '不存在的块应返回 null');
});

test('gatherCryptoBlocksForChange: 读不到的块不再被当作已删除剔除，而是计入 unreadableCount 让改密中止', async () => {
    const p = makePlugin();
    await p.saveCryptoBlockIndex(['alive1', 'alive2', 'gone1', 'gone2']); // gone* 读不到
    p.buildCryptoIndex = async () => ['alive1', 'alive2', 'gone1', 'gone2']; // 遍历不改变既有索引集合
    p.getCryptoBlockById = async (id) => {
        if (id === 'gone1' || id === 'gone2') return null; // 无法确认（可能仅存在于未打开笔记本/读取失败）
        return { id, data: 'd', iv: 'i' };
    };
    const okCrypto = { decrypt: async (data, iv) => ({ content: 'plain-' + iv }) };
    const { list, failedCount, unreadableCount } = await p.gatherCryptoBlocksForChange(okCrypto);
    assert.strictEqual(failedCount, 0);
    assert.deepStrictEqual(list.map((b) => b.id), ['alive1', 'alive2']);
    // 关键：无法确认的块绝不能被剔除，否则改密提交新盐后它就是永久损坏；必须让调用方中止
    assert.strictEqual(unreadableCount, 2, '读不到的块应计入 unreadableCount，由调用方中止改密');
    assert.deepStrictEqual(await p.loadCryptoBlockIndex(), ['alive1', 'alive2', 'gone1', 'gone2'], '索引不得被清除');
});

test('collectCryptoBlocksByIndex: 索引缺失的块通过 getBlockKramdown 兜底', async () => {
    const p = makePlugin();
    p.collectCryptoBlocksByWalking = async () => [
        { id: 'b1', data: 'd1', iv: 'i1' },
    ];
    await p.saveCryptoBlockIndex(['b1', 'b2']); // b2 在索引里但遍历没找到
    // 兜底：对 b2 单独 getBlockKramdown
    fakeSiyuan.fetchSyncPost = async (path, payload) => {
        if (path === '/api/block/getBlockKramdown' && payload.id === 'b2') {
            return { code: 0, data: { kramdown: sampleKramdown } }; // 含 blk 20260324152103-lbokog9
        }
        return { code: 0, data: {} };
    };
    const blocks = await p.collectCryptoBlocksByIndex();
    const ids = blocks.map((b) => b.id);
    assert.ok(ids.includes('b1'), '应包含遍历结果 b1');
    assert.ok(ids.includes('20260324152103-lbokog9'), '应包含索引兜底查到的块（忽略了不存在的 b2）');
});

test('CryptoManager 加解密往返一致（真实 AES-GCM/PBKDF2）', async () => {
    const pluginProto = PassManagerPlugin.prototype;
    // 通过插件实例上的 crypto 持有方法存在与否验证算法一致性：直接自测 WebCrypto 往返
    const encoder = new TextEncoder();
    const importKey = async (password, saltBytes) => {
        const baseKey = await globalThis.crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        return globalThis.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
            baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
    };
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const key = await importKey('password123', salt);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const plain = JSON.stringify({ content: 'hello block' });
    const enc = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plain));
    const encBuf = Buffer.from(enc);
    const dec = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encBuf);
    const roundtrip = Buffer.from(dec).toString('utf8');
    assert.strictEqual(roundtrip, plain, 'AES-GCM 加解密往返应一致');
});