const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

function activate(context) {
    let disposable = vscode.commands.registerCommand('funcsandbox.sandboxfunction', () => {
        let editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'python') {
            vscode.window.showErrorMessage('Please select a Python function.');
            return;
        }

        let selection = editor.selection;
        let text = editor.document.getText(selection);
        
        // Analyze the Python function to extract operations
        let promises = analyzePythonFunction(text);
        let sandbox =  Array.from(promises).join(' ');

        // Get the position to insert the comment
        let functionStart = editor.document.offsetAt(selection.start);
        let line = editor.document.positionAt(functionStart).line;

        // Insert comment above the function
        editor.edit(editBuilder => {
            editBuilder.insert(new vscode.Position(line, 0), `@sandbox_function("${sandbox}")` + '\n');
        });
    });

    context.subscriptions.push(disposable);
}

function analyzePythonFunction(code, analyzedFunctions = new Set(), projectDir = '/home/null/project_dir/') {
    const promises = new Set();

    const promiseMappings = {
        'proc': ['os.fork', 'os.nice', 'os.system', 'resource.prlimit', 'resource.setrlimit', 'os.sched_setscheduler', 'os.kill', 'fcntl.prctl'],
        'wpath': ['builtins.open', 'os.mkdir', 'os.rmdir', 'os.unlink', 'os.symlink', 'os.link', 'os.rename', 'os.truncate', 'os.chmod', 'os.chown', 'os.mknod'],
        'net': ['socket.socket', 'socket.create_connection', 'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.getaddrinfo', 'socket.getnameinfo', 'socket.gethostbyaddr', 'socket.getaddrinfo', 'socket.getnameinfo'],
    };

    let currentName = code.match(/\bdef\s+(\w+)/);
    console.log(currentName[1]);
    analyzedFunctions.add(currentName[1]);

    for (const [promise, funcs] of Object.entries(promiseMappings)) {
        for (const func of funcs) {
            if (code.includes(func)) {
                promises.add(promise);
            }
        }
    }

    const functionCallsRegex = /(\w+)\s*\(/g;
    let match;
    while ((match = functionCallsRegex.exec(code))) {
        const functionName = match[1];
        console.log(functionName);
        if (analyzedFunctions.has(functionName)) continue;

        const functionCode = getFunctionCode(functionName, projectDir);
        if (functionCode) {
            const functionPromises = analyzePythonFunction(functionCode, analyzedFunctions, projectDir);
            functionPromises.forEach(p => promises.add(p));
        }
    }

    return promises;
}

// Locate the definition of a function in the same file or project
function getFunctionCode(functionName, projectDir) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active text editor.');
        return '';
    }

    const document = editor.document;
    const text = document.getText();

    const functionRegex = new RegExp(`def\\s+${functionName}\\s*\\(.*?\\):[\\s\\S]*?(?=\\bdef\\s+|class\\s+|$)`, 'g');
    const matches = text.match(functionRegex);
    if (matches) return matches[0];

    return '';
}

function searchFunctionInProject(functionName, projectDir) {
    const pythonFiles = getAllPythonFiles(projectDir);

    for (const file of pythonFiles) {
        const content = fs.readFileSync(file, 'utf8');
        const functionRegex = new RegExp(`def\\s+${functionName}\\s*\\(.*?\\):[\\s\\S]*?(?=\\bdef\\s+|class\\s+|$)`, 'g');
        const matches = content.match(functionRegex);
        if (matches) return matches[0];
    }

    return '';
}

// Get all Python files in the project directory
function getAllPythonFiles(projectDir) {
    let pythonFiles = [];
    function scanDir(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            if (fs.statSync(fullPath).isDirectory()) {
                scanDir(fullPath);
            } else if (file.endsWith('.py')) {
                pythonFiles.push(fullPath);
            }
        }
    }
    scanDir(projectDir);
    console.log(pythonFiles);
    return pythonFiles;
}

module.exports = {
    activate
};
