-- Initialize the random number generator
math.randomseed(os.time())

-- bench with most common domains worldwide from https://radar.cloudflare.com/domains
local domains = {
    "google.com",
    "googleapis.com",
    "apple.com",
    "gstatic.com",
    "facebook.com",
    "amazonaws.com",
    "microsoft.com",
    "tiktokcdn.com",
    "googlevideo.com",
    "cloudflare.com",
    "youtube.com",
    "icloud.com",
    "amazon.com",
    "tiktokv.com",
    "instagram.com",
    "googleusercontent.com",
    "googlesyndication.com",
    "gvt2.com",
    "cloudflare-dns.com",
    "netflix.com",
    "ytimg.com",
    "bing.com",
    "cdninstagram.com",
    "live.com",
    "aaplimg.com",
    "google-analytics.com",
    "spotify.com",
    "bytefcdn-oversea.com",
    "yahoo.com",
    "snapchat.com",
    "app-measurement.com",
    "gvt1.com",
    "unity3d.com",
    "twitter.com",
    "office.com",
    "googleadservices.com",
    "ttlivecdn.com",
    "amazon-adsystem.com",
    "app-analytics-services.com",
    "ui.com",
    "digicert.com",
    "applovin.com",
    "msftncsi.com",
    "roblox.com",
    "ggpht.com",
    "samsung.com",
    "googletagmanager.com",
    "baidu.com",
    "azure.com",
    "criteo.com",
    "skype.com",
    "msn.com",
    "xiaomi.com",
    "bytefcdn-ttpeu.com",
    "rocket-cdn.com",
    "rbxcdn.com",
    "office365.com",
    "gmail.com",
    "android.com",
    "linkedin.com",
    "microsoftonline.com",
    "qq.com",
    "tiktokcdn-us.com",
    "example.com",
    "windows.com",
    "doubleverify.com",
    "appsflyersdk.com",
    "taboola.com",
    "cdn-apple.com",
    "windowsupdate.com",
    "ring.com",
    "qlivecdn.com",
    "smartadserver.com",
    "mzstatic.com",
    "casalemedia.com",
    "miui.com",
    "vungle.com"
}

-- Request function
request = function()
   local domain = domains[math.random(#domains)]
   local path = string.format("/dns-query?name=%s&type=A", domain)
   return wrk.format("GET", path, {["Accept"] = "application/dns-json"})
end

-- Response handling
response = function(status, headers, body)
   if status ~= 200 then
      print("Error: " .. status)
   end
end

done = function(summary, latency, requests)
    io.write("------------------------------\n")
    io.write(string.format("Total Requests: %d\n", summary.requests))
    io.write(string.format("Avg. Latency: %.3f ms\n", latency.mean/1000))
    io.write(string.format("Max Latency: %.3f ms\n", latency.max/1000))
    io.write(string.format("50th percentile: %.3f ms\n", latency:percentile(50)/1000))
    io.write(string.format("90th percentile: %.3f ms\n", latency:percentile(90)/1000))
    io.write(string.format("99th percentile: %.3f ms\n", latency:percentile(99)/1000))
    io.write("------------------------------\n")
end