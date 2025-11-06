import axios from "axios";

export const checkMaliciousUrl = async (req, res, next) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ msg: "URL is required" });

    const vtKey = process.env.VIRUSTOTAL_API_KEY;

    try {

        /* ----------------- 🔹 2. VirusTotal Check ----------------- */
        if (!vtKey) throw new Error("Missing VirusTotal API key");

        // Step 1: Submit URL for scanning (VirusTotal requires encoding)
        const encodedUrl = Buffer.from(url).toString("base64").replace(/=+$/, "");

        // Step 2: Fetch analysis result
        const vtRes = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
            headers: { "x-apikey": vtKey },
        });

        const stats = vtRes.data.data.attributes.last_analysis_stats;

        // If multiple engines flagged the URL, treat as malicious
        if (stats.malicious > 0 || stats.suspicious > 0) {
            return res.status(400).json({
                msg: "🚫 URL flagged as unsafe by VirusTotal",
                stats,
            });
        }

        /* ----------------- ✅ Safe URL ----------------- */
        console.log("URL Passed All Checks:", url);
        req.link = url;
        next();

    } catch (error) {
        console.error("Safe Browsing or VirusTotal check failed:", error.response?.data || error.message);
        // Fallback: allow request if reputation services fail
        req.link = url;
        next();
    }
};
