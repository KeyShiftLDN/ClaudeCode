import { spawn } from "child_process";
import { homedir } from "os";
import { join } from "path";
export async function executeHttpx(urls, followRedirects = false, screenshot = false) {
    return new Promise((resolve) => {
        const args = ["-j", "-silent"];
        if (followRedirects)
            args.push("-fr");
        if (screenshot)
            args.push("-screenshot");
        const responses = [];
        let errorOutput = "";
        // Use the Go-installed httpx (newer version)
        const httpxPath = join(homedir(), "go", "bin", "httpx");
        const process = spawn(httpxPath, args);
        // Feed URLs via stdin
        process.stdin.write(urls.join("\n") + "\n");
        process.stdin.end();
        process.stdout.on("data", (data) => {
            const lines = data.toString().split("\n").filter((line) => line.trim());
            for (const line of lines) {
                try {
                    const parsed = JSON.parse(line);
                    responses.push({
                        url: parsed.url || parsed.host,
                        statusCode: parsed.status_code,
                        contentLength: parsed.content_length,
                        title: parsed.title,
                        webserver: parsed.webserver,
                    });
                }
                catch (e) {
                    // Skip unparseable lines
                }
            }
        });
        process.stderr.on("data", (data) => {
            errorOutput += data.toString();
        });
        process.on("close", (code) => {
            if (code !== 0 && responses.length === 0) {
                resolve({
                    responses: [],
                    count: 0,
                    error: `httpx exited with code ${code}: ${errorOutput}`,
                });
            }
            else {
                resolve({
                    responses,
                    count: responses.length,
                });
            }
        });
        process.on("error", (err) => {
            resolve({
                responses: [],
                count: 0,
                error: `Failed to execute httpx: ${err.message}. Make sure httpx is installed.`,
            });
        });
    });
}
