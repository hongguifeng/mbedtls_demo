const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

const EXAMPLES = [
    { name: '01_hash',           sub: 'mbedtls_36', desc: '哈希/摘要算法' },
    { name: '02_aes',            sub: 'mbedtls_36', desc: '对称加密 (AES)' },
    { name: '03_rsa',            sub: 'mbedtls_36', desc: '非对称加密 (RSA)' },
    { name: '04_ecc',            sub: 'mbedtls_36', desc: '椭圆曲线密码学' },
    { name: '05_x509_parse',     sub: 'mbedtls_36', desc: 'X.509 证书解析' },
    { name: '06_tls_client',     sub: 'mbedtls_36', desc: 'TLS 客户端 (需要网络)' },
    { name: '07_tls_mutual',     sub: 'mbedtls_36', desc: 'TLS 双向认证 (本地)' },
    { name: '08_custom_bio',     sub: 'mbedtls_36', desc: '自定义 BIO (需要网络)' },
    { name: '09_psa_hash',       sub: 'mbedtls_42', desc: 'PSA 哈希/摘要' },
    { name: '10_psa_cipher',     sub: 'mbedtls_42', desc: 'PSA 对称加密 (AES-CBC/CTR)' },
    { name: '11_psa_aead',       sub: 'mbedtls_42', desc: 'PSA AEAD (AES-GCM)' },
    { name: '12_psa_mac',        sub: 'mbedtls_42', desc: 'PSA MAC (HMAC/CMAC)' },
    { name: '13_psa_asymmetric', sub: 'mbedtls_42', desc: 'PSA 非对称 (ECC/RSA 签名)' },
    { name: '14_psa_kdf',        sub: 'mbedtls_42', desc: 'PSA KDF (HKDF/ECDH)' },
    { name: '15_psa_key_mgmt',   sub: 'mbedtls_42', desc: 'PSA 密钥管理' },
];

function activate(context) {
    context.subscriptions.push(
        vscode.commands.registerCommand('mbedtlsDemo.runExample', runExample)
    );
}

async function runExample() {
    const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
    if (!folder) {
        vscode.window.showErrorMessage('请先打开 mbedtls_demo 工作区');
        return;
    }
    const root = folder.uri.fsPath;

    const items = EXAMPLES.map((e) => ({
        label: e.name,
        // 用前缀区分两个子项目，Quick Pick 里一目了然
        description: `[${e.sub}] ${e.desc}`,
        detail: `${e.sub}/build/${e.name}`,
        example: e,
    }));

    const picked = await vscode.window.showQuickPick(items, {
        placeHolder: '选择要运行的示例 (01-15)，支持输入名称过滤',
        matchOnDescription: true,
    });
    if (!picked) {
        return;
    }

    const e = picked.example;
    const exe = path.join(root, e.sub, 'build', e.name);

    if (!fs.existsSync(exe)) {
        const choice = await vscode.window.showWarningMessage(
            `可执行文件不存在: ${e.sub}/build/${e.name}，是否先构建？`,
            '先构建',
            '取消'
        );
        if (choice === '先构建') {
            const tasks = await vscode.tasks.fetchTasks();
            const task = tasks.find((t) => t.name === `Build ${e.name}`);
            if (task) {
                await vscode.tasks.executeTask(task);
            } else {
                vscode.window.showErrorMessage(`找不到构建任务: Build ${e.name}`);
            }
        }
        return;
    }

    const term = vscode.window.createTerminal(`Run ${e.name}`);
    term.sendText(`cd "${path.join(root, e.sub)}" && ./${e.name}`);
    term.show();
}

function deactivate() {}

module.exports = { activate, deactivate };
