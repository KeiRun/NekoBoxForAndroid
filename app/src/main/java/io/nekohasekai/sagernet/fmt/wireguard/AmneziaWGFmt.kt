package io.nekohasekai.sagernet.fmt.wireguard

import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.group.RawUpdater
import io.nekohasekai.sagernet.ktx.linkBuilder
import io.nekohasekai.sagernet.ktx.toLink
import io.nekohasekai.sagernet.ktx.toStringPretty
import io.nekohasekai.sagernet.ktx.wrapIPV6Host
import moe.matsuri.nb4a.SingBoxOptions
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Locale
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

private const val AMNEZIAWG_SCHEME = "amneziawg://"
private const val AMNEZIAWG_SHORT_SCHEME = "awg://"

fun extractConfProfileName(conf: String): String? {
    val explicitRegex = Regex("""(?im)^\s*[#;]\s*(?:Name|Profile|Description|Profile-Title|Title)\s*[:=]\s*(.+?)\s*$""")
    explicitRegex.find(conf)?.groupValues?.get(1)?.trim()?.takeIf { it.isNotBlank() }?.let { return it }

    for (rawLine in conf.lineSequence()) {
        val trimmed = rawLine.trim()
        if (trimmed.isEmpty()) continue
        if (trimmed.startsWith('[')) break
        if (trimmed.startsWith('#') || trimmed.startsWith(';')) {
            val comment = trimmed.drop(1).trim()
            if (comment.isNotBlank() &&
                !comment.startsWith('[') &&
                !comment.contains('=') &&
                !comment.startsWith("profile-title:", ignoreCase = true) &&
                !comment.startsWith("WireGuard", ignoreCase = true) &&
                !comment.startsWith("AmneziaWG", ignoreCase = true) &&
                !comment.startsWith("Configuration", ignoreCase = true)
            ) {
                return comment
            }
        }
    }
    return null
}

internal fun isAwg31Name(name: String?): Boolean {
    if (name.isNullOrBlank()) return false
    val lower = name.lowercase(Locale.ROOT)
    return lower.contains("awg3.1") ||
        lower.contains("awg 3.1") ||
        lower.contains("amneziawg3.1") ||
        lower.contains("amneziawg 3.1") ||
        lower.contains("awg-3.1") ||
        lower.contains("awg_3.1") ||
        lower.contains("awg31") ||
        lower.contains("awg-v3.1") ||
        lower.contains("awg-v31") ||
        lower.contains("awg v3.1") ||
        lower.contains("awg v31")
}

private val throneAmneziaParameters = setOf(
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    "header_protection_key", "content_padding_addition", "rekey_after_time",
    "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts",
    "random_trailers", "randomtrailers", "random_trailer", "randomtrailer",
    "randomizetrailers", "randomize_trailers", "trailers", "trailer", "rt",
    "disable_cookies", "disablecookies", "disable_cookie", "disablecookie",
    "no_cookies", "nocookies", "dc",
    "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime",
    "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts",
)

fun parseThroneWireGuardUri(url: String): AbstractBean {
    requireNotNull(url.replaceBefore("://", "https").toHttpUrlOrNull()) {
        "Invalid WireGuard link"
    }
    val wireGuard = parseWireGuardUri(url)
    val isAmnezia = url.throneQueryParameter("enable_amnezia") == "true" ||
        throneAmneziaParameters.any { url.throneQueryParameter(it) != null }
    if (!isAmnezia) return wireGuard

    return AmneziaWGBean().apply {
        initializeDefaultValues()
        name = wireGuard.name
        serverAddress = wireGuard.serverAddress
        serverPort = wireGuard.serverPort
        localAddress = wireGuard.localAddress
        privateKey = wireGuard.privateKey
        peerPublicKey = wireGuard.peerPublicKey
        peerPreSharedKey = wireGuard.peerPreSharedKey
        peerPersistentKeepalive = url.throneQueryParameter("persistent_keepalive_interval")
            ?: url.throneQueryParameter("keepalive")
            ?: "0"
        mtu = wireGuard.mtu
        reserved = wireGuard.reserved
        url.throneQueryParameter("jc")?.toIntOrNull()?.let { jc = it }
        url.throneQueryParameter("jmin")?.toIntOrNull()?.let { jmin = it }
        url.throneQueryParameter("jmax")?.toIntOrNull()?.let { jmax = it }
        url.throneQueryParameter("s1")?.toIntOrNull()?.let { s1 = it }
        url.throneQueryParameter("s2")?.toIntOrNull()?.let { s2 = it }
        url.throneQueryParameter("s3")?.toIntOrNull()?.let { s3 = it }
        url.throneQueryParameter("s4")?.toIntOrNull()?.let { s4 = it }
        url.throneQueryParameter("h1")?.let { h1 = it }
        url.throneQueryParameter("h2")?.let { h2 = it }
        url.throneQueryParameter("h3")?.let { h3 = it }
        url.throneQueryParameter("h4")?.let { h4 = it }
        url.throneQueryParameter("i1")?.let { i1 = it }
        url.throneQueryParameter("i2")?.let { i2 = it }
        url.throneQueryParameter("i3")?.let { i3 = it }
        url.throneQueryParameter("i4")?.let { i4 = it }
        url.throneQueryParameter("i5")?.let { i5 = it }
        (url.throneQueryParameter("header_protection_key") ?: url.throneQueryParameter("headerprotectionkey"))
            ?.let { headerProtectionKey = it }
        (url.throneQueryParameter("content_padding_addition") ?: url.throneQueryParameter("contentpaddingaddition"))
            ?.let { contentPaddingAddition = it }
        (url.throneQueryParameter("rekey_after_time") ?: url.throneQueryParameter("rekeyaftertime"))
            ?.let { rekeyAfterTime = it }
        (url.throneQueryParameter("rekey_timeout") ?: url.throneQueryParameter("rekeytimeout"))
            ?.let { rekeyTimeout = it }
        (url.throneQueryParameter("reject_after_time") ?: url.throneQueryParameter("rejectaftertime"))
            ?.let { rejectAfterTime = it }
        (url.throneQueryParameter("keepalive_timeout") ?: url.throneQueryParameter("keepalivetimeout"))
            ?.let { keepaliveTimeout = it }
        (url.throneQueryParameter("max_handshake_attempts") ?: url.throneQueryParameter("maxhandshakeattempts"))
            ?.let { maxHandshakeAttempts = it }
        val hasRandomTrailers = listOf(
            "random_trailers", "randomtrailers", "random_trailer", "randomtrailer",
            "randomizetrailers", "randomize_trailers", "trailers", "trailer", "rt",
        ).firstNotNullOfOrNull { key ->
            url.throneQueryParameter(key)?.let(::parseAmneziaWGToggle)
        }
        val hasDisableCookies = listOf(
            "disable_cookies", "disablecookies", "disable_cookie", "disablecookie",
            "no_cookies", "nocookies", "dc",
        ).firstNotNullOfOrNull { key ->
            url.throneQueryParameter(key)?.let(::parseAmneziaWGToggle)
        }
        val isAwg31 = isAwg31Name(name) || hasRandomTrailers == true || hasDisableCookies == true
        randomTrailers = hasRandomTrailers ?: (if (isAwg31) true else false)
        disableCookies = hasDisableCookies ?: (if (isAwg31 || randomTrailers == true) true else false)
    }
}

internal fun parseAmneziaWGToggle(value: String?): Boolean? =
    when (value?.trim()?.lowercase(Locale.ROOT)) {
        "1", "true", "yes", "on", "enabled", "" -> true
        "0", "false", "no", "off", "disabled" -> false
        else -> null
    }

internal fun AmneziaWGBean.applyAmneziaWG3Options(option: (String) -> String?) {
    fun findOption(vararg names: String): String? {
        for (n in names) {
            val v = option(n)
            if (!v.isNullOrBlank()) return v
        }
        return null
    }

    findOption("HeaderProtectionKey", "header_protection_key", "headerprotectionkey")?.let { headerProtectionKey = it }
    findOption("ContentPaddingAddition", "content_padding_addition", "contentpaddingaddition")?.let { contentPaddingAddition = it }
    findOption("RekeyAfterTime", "rekey_after_time", "rekeyaftertime")?.let { rekeyAfterTime = it }
    findOption("RekeyTimeout", "rekey_timeout", "rekeytimeout")?.let { rekeyTimeout = it }
    findOption("RejectAfterTime", "reject_after_time", "rejectaftertime")?.let { rejectAfterTime = it }
    findOption("KeepaliveTimeout", "keepalive_timeout", "keepalivetimeout")?.let { keepaliveTimeout = it }
    findOption("MaxHandshakeAttempts", "max_handshake_attempts", "maxhandshakeattempts")?.let { maxHandshakeAttempts = it }

    val rtOption = findOption(
        "RandomTrailers", "random_trailers", "randomtrailers",
        "RandomTrailer", "random_trailer", "randomtrailer",
        "RandomizeTrailers", "randomize_trailers", "randomizetrailers",
        "Trailers", "trailers", "Trailer", "trailer",
        "RT", "rt",
    )
    val parsedRt = parseAmneziaWGToggle(rtOption)
    if (parsedRt != null) randomTrailers = parsedRt

    val dcOption = findOption(
        "DisableCookies", "disable_cookies", "disablecookies",
        "DisableCookie", "disable_cookie", "disablecookie",
        "NoCookies", "no_cookies", "nocookies",
        "DC", "dc",
    )
    val parsedDc = parseAmneziaWGToggle(dcOption)
    if (parsedDc != null) disableCookies = parsedDc

    val isAwg31 = isAwg31Name(name) || randomTrailers == true
    if (isAwg31) {
        if (randomTrailers != false) randomTrailers = true
        if (disableCookies != false) disableCookies = true
    }
}

fun parseAmneziaWGUri(link: String): List<AmneziaWGBean> {
    val trimmed = link.trim()
    val scheme = when {
        trimmed.startsWith(AMNEZIAWG_SCHEME, ignoreCase = true) -> AMNEZIAWG_SCHEME
        trimmed.startsWith(AMNEZIAWG_SHORT_SCHEME, ignoreCase = true) -> AMNEZIAWG_SHORT_SCHEME
        else -> error("Invalid AmneziaWG link")
    }
    val payload = trimmed.substring(scheme.length)
    require(payload.isNotBlank()) { "Missing AmneziaWG config" }

    val beforeFragment = payload.substringBefore('#')
    val fragmentName = payload.substringAfter('#', "")
        .takeIf(String::isNotBlank)
        ?.let(::decodeFragment)

    if (beforeFragment.contains('@') || beforeFragment.contains('?')) {
        return listOf(parseAmneziaWGStandardUri(trimmed, fragmentName))
    }

    val config = runCatching { decodeUrlSafeBase64(beforeFragment) }.getOrElse {
        return listOf(parseAmneziaWGStandardUri(trimmed, fragmentName))
    }
    return parseNamedAmneziaWGConfig(config, fragmentName)
}

private fun parseAmneziaWGStandardUri(url: String, explicitName: String?): AmneziaWGBean {
    val afterScheme = url.substringAfter("://")
    val beforeFragment = afterScheme.substringBefore('#')
    val fragmentName = explicitName ?: url.substringAfter('#', "").takeIf(String::isNotBlank)?.let(::decodeFragment)

    val authorityPart = beforeFragment.substringBefore('?')
    val queryPart = if (beforeFragment.contains('?')) beforeFragment.substringAfter('?') else ""

    var extractedPrivateKey = ""
    val hostAndPort: String
    if (authorityPart.contains('@')) {
        val userinfo = authorityPart.substringBeforeLast('@')
        hostAndPort = authorityPart.substringAfterLast('@')
        extractedPrivateKey = runCatching { URLDecoder.decode(userinfo.replace("+", "%2B"), "UTF-8") }.getOrDefault(userinfo)
    } else {
        hostAndPort = authorityPart
    }

    val host: String
    val port: Int
    if (hostAndPort.startsWith('[')) {
        host = hostAndPort.substringBefore(']').removePrefix("[")
        port = hostAndPort.substringAfter("]:", "").toIntOrNull() ?: -1
    } else {
        host = hostAndPort.substringBeforeLast(':')
        port = hostAndPort.substringAfterLast(':', "").toIntOrNull() ?: -1
    }
    require(host.isNotBlank() && port > 0) { "Invalid WireGuard endpoint" }

    val queryParams = mutableMapOf<String, String>()
    val presentKeys = mutableSetOf<String>()
    if (queryPart.isNotEmpty()) {
        for (part in queryPart.split('&')) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            val rawK = if (eq >= 0) part.substring(0, eq) else part
            val rawV = if (eq >= 0) part.substring(eq + 1) else ""
            val normK = rawK.trim().lowercase(Locale.ROOT).replace("_", "").replace("-", "")
            val decodedV = runCatching { URLDecoder.decode(rawV.replace("+", "%2B"), "UTF-8") }.getOrDefault(rawV)
            presentKeys.add(normK)
            queryParams[normK] = decodedV
        }
    }

    return AmneziaWGBean().apply {
        initializeDefaultValues()
        name = fragmentName ?: host
        serverAddress = host
        serverPort = port
        privateKey = extractedPrivateKey.ifBlank { queryParams["privatekey"] }.orEmpty()
        peerPublicKey = queryParams["publickey"] ?: queryParams["peerpublickey"] ?: ""
        peerPreSharedKey = queryParams["presharedkey"] ?: queryParams["preshared"] ?: ""

        val rawAddress = queryParams["address"] ?: queryParams["localaddress"] ?: ""
        localAddress = rawAddress.split(',', '-', '\n').map(String::trim).filter(String::isNotEmpty).joinToString("\n")

        peerPersistentKeepalive = queryParams["keepalive"]
            ?: queryParams["persistentkeepalive"]
            ?: queryParams["persistentkeepaliveinterval"]
            ?: "0"
        mtu = queryParams["mtu"]?.toIntOrNull() ?: 1280
        reserved = queryParams["reserved"]
            ?.split(',', '-')
            ?.mapNotNull(String::toIntOrNull)
            ?.takeIf { it.size == 3 }
            ?.joinToString(",")
            .orEmpty()

        // AWG 1.0
        queryParams["jc"]?.toIntOrNull()?.let { jc = it }
        queryParams["jmin"]?.toIntOrNull()?.let { jmin = it }
        queryParams["jmax"]?.toIntOrNull()?.let { jmax = it }
        queryParams["s1"]?.toIntOrNull()?.let { s1 = it }
        queryParams["s2"]?.toIntOrNull()?.let { s2 = it }
        queryParams["h1"]?.let { h1 = it }
        queryParams["h2"]?.let { h2 = it }
        queryParams["h3"]?.let { h3 = it }
        queryParams["h4"]?.let { h4 = it }

        // AWG 1.5
        queryParams["i1"]?.let { i1 = it }
        queryParams["i2"]?.let { i2 = it }
        queryParams["i3"]?.let { i3 = it }
        queryParams["i4"]?.let { i4 = it }
        queryParams["i5"]?.let { i5 = it }

        // AWG 2.0
        queryParams["s3"]?.toIntOrNull()?.let { s3 = it }
        queryParams["s4"]?.toIntOrNull()?.let { s4 = it }

        // AWG 3.0
        queryParams["headerprotectionkey"]?.let { headerProtectionKey = it }
        queryParams["contentpaddingaddition"]?.let { contentPaddingAddition = it }
        queryParams["rekeyaftertime"]?.let { rekeyAfterTime = it }
        queryParams["rekeytimeout"]?.let { rekeyTimeout = it }
        queryParams["rejectaftertime"]?.let { rejectAfterTime = it }
        queryParams["keepalivetimeout"]?.let { keepaliveTimeout = it }
        queryParams["maxhandshakeattempts"]?.let { maxHandshakeAttempts = it }

        // AWG 3.1
        val rtKeys = listOf(
            "randomtrailers", "randomtrailer", "randomizetrailers", "randomizetrailer",
            "trailers", "trailer", "rt",
        )
        val rtVal = rtKeys.firstNotNullOfOrNull { queryParams[it] }
        val rtInPresent = rtKeys.any { it in presentKeys }
        val parsedRt = parseAmneziaWGToggle(rtVal) ?: if (rtInPresent) true else null

        val dcKeys = listOf(
            "disablecookies", "disablecookie", "nocookies", "nocookie", "dc",
        )
        val dcVal = dcKeys.firstNotNullOfOrNull { queryParams[it] }
        val dcInPresent = dcKeys.any { it in presentKeys }
        val parsedDc = parseAmneziaWGToggle(dcVal) ?: if (dcInPresent) true else null

        val isAwg31 = isAwg31Name(fragmentName ?: host) || parsedRt == true
        randomTrailers = parsedRt ?: (if (isAwg31) true else false)
        disableCookies = parsedDc ?: (if (isAwg31 || randomTrailers == true) true else false)

        require(privateKey.isNotBlank()) { "Missing WireGuard private key" }
        require(peerPublicKey.isNotBlank()) { "Missing WireGuard peer public key" }
    }
}

fun AmneziaWGBean.toAmneziaWGUri(): String {
    val builder = linkBuilder().host(serverAddress).port(serverPort)
    val addresses = normalizeWireGuardAddressList(localAddress)
    if (addresses.isNotEmpty()) builder.addQueryParameter("address", addresses.joinToString(","))
    if (peerPublicKey.isNotBlank()) builder.addQueryParameter("publickey", peerPublicKey)
    if (peerPreSharedKey.isNotBlank()) builder.addQueryParameter("presharedkey", peerPreSharedKey)
    if (peerPersistentKeepalive.isNotBlank() && peerPersistentKeepalive != "0") {
        builder.addQueryParameter("keepalive", peerPersistentKeepalive)
    }
    if (mtu > 0 && mtu != 1280) builder.addQueryParameter("mtu", mtu.toString())
    if (reserved.isNotBlank()) {
        parseReservedValues(reserved)?.let {
            builder.addQueryParameter("reserved", it.joinToString("-"))
        }
    }
    if (jc != 0) builder.addQueryParameter("jc", jc.toString())
    if (jmin != 0) builder.addQueryParameter("jmin", jmin.toString())
    if (jmax != 0) builder.addQueryParameter("jmax", jmax.toString())
    if (s1 != 0) builder.addQueryParameter("s1", s1.toString())
    if (s2 != 0) builder.addQueryParameter("s2", s2.toString())
    if (h1.isNotBlank()) builder.addQueryParameter("h1", h1)
    if (h2.isNotBlank()) builder.addQueryParameter("h2", h2)
    if (h3.isNotBlank()) builder.addQueryParameter("h3", h3)
    if (h4.isNotBlank()) builder.addQueryParameter("h4", h4)
    if (i1.isNotBlank()) builder.addQueryParameter("i1", i1)
    if (i2.isNotBlank()) builder.addQueryParameter("i2", i2)
    if (i3.isNotBlank()) builder.addQueryParameter("i3", i3)
    if (i4.isNotBlank()) builder.addQueryParameter("i4", i4)
    if (i5.isNotBlank()) builder.addQueryParameter("i5", i5)
    if (s3 != 0) builder.addQueryParameter("s3", s3.toString())
    if (s4 != 0) builder.addQueryParameter("s4", s4.toString())
    if (headerProtectionKey.isNotBlank()) builder.addQueryParameter("headerprotectionkey", headerProtectionKey)
    if (contentPaddingAddition.isNotBlank()) builder.addQueryParameter("contentpaddingaddition", contentPaddingAddition)
    if (rekeyAfterTime.isNotBlank()) builder.addQueryParameter("rekeyaftertime", rekeyAfterTime)
    if (rekeyTimeout.isNotBlank()) builder.addQueryParameter("rekeytimeout", rekeyTimeout)
    if (rejectAfterTime.isNotBlank()) builder.addQueryParameter("rejectaftertime", rejectAfterTime)
    if (keepaliveTimeout.isNotBlank()) builder.addQueryParameter("keepalivetimeout", keepaliveTimeout)
    if (maxHandshakeAttempts.isNotBlank()) builder.addQueryParameter("maxhandshakeattempts", maxHandshakeAttempts)
    val isAwg31 = randomTrailers == true || disableCookies == true || isAwg31Name(name)
    if (randomTrailers == true || isAwg31) builder.addQueryParameter("randomtrailers", "true")
    if (disableCookies == true || isAwg31) builder.addQueryParameter("disablecookies", "true")

    if (name.isNotBlank()) builder.fragment(name)
    val link = builder.toLink("amneziawg").replace(":$serverPort/", ":$serverPort")
    return if (privateKey.isNotBlank()) {
        val encodedKey = URLEncoder.encode(privateKey, "UTF-8")
        link.replace("amneziawg://", "amneziawg://$encodedKey@")
    } else {
        link
    }
}

fun parseAmneziaWGJsonContainer(json: JSONObject): List<AmneziaWGBean> {
    require(json.optString("type") == "amneziawg") { "Invalid AmneziaWG JSON container" }
    val servers = json.optJSONArray("servers") ?: error("Missing AmneziaWG servers")
    val results = mutableListOf<AmneziaWGBean>()
    val seenConfigs = mutableSetOf<String>()
    for (index in 0 until servers.length()) {
        val server = servers.optJSONObject(index) ?: continue
        val encoded = server.optString("config").takeIf(String::isNotBlank) ?: continue
        runCatching {
            val config = decodeUrlSafeBase64(encoded)
            if (seenConfigs.add(config)) {
                results += parseNamedAmneziaWGConfig(
                    config,
                    server.optString("name").takeIf(String::isNotBlank),
                )
            }
        }
    }
    return results
}

fun buildAmneziaWGJsonContainer(beans: List<AmneziaWGBean>): String {
    val servers = JSONArray()
    beans.forEach { bean ->
        servers.put(
            JSONObject()
                .put("name", bean.displayName())
                .put("config", encodeUrlSafeBase64(bean.buildAmneziaWGConfig())),
        )
    }
    return JSONObject()
        .put("type", "amneziawg")
        .put("version", 1)
        .put("servers", servers)
        .toStringPretty()
}

private fun parseNamedAmneziaWGConfig(
    config: String,
    explicitName: String?,
): List<AmneziaWGBean> {
    val commentName = extractConfProfileName(config)
    return RawUpdater.parseAmneziaWG(config).onEach { bean ->
        bean.name = explicitName ?: commentName ?: bean.name.takeIf(String::isNotBlank) ?: bean.serverAddress
        if (isAwg31Name(bean.name) || bean.randomTrailers == true) {
            bean.randomTrailers = true
            bean.disableCookies = true
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
private fun encodeUrlSafeBase64(value: String): String =
    Base64.UrlSafe.encode(value.toByteArray()).trimEnd('=')

@OptIn(ExperimentalEncodingApi::class)
private fun decodeUrlSafeBase64(value: String): String {
    val padded = value.padEnd(value.length + (4 - value.length % 4) % 4, '=')
    return Base64.UrlSafe.decode(padded).toString(Charsets.UTF_8)
}

private fun encodeFragment(value: String): String = HttpUrl.Builder()
    .scheme("https")
    .host("fragment.invalid")
    .fragment(value)
    .build()
    .encodedFragment
    .orEmpty()

private fun decodeFragment(value: String): String =
    "https://fragment.invalid/#$value".toHttpUrlOrNull()?.fragment
        ?: runCatching { URLDecoder.decode(value, "UTF-8") }.getOrDefault(value)

fun AmneziaWGBean.buildAmneziaWGConfig(): String = buildString {
    if (name.isNotBlank()) append("# ").append(name).append('\n')
    append("[Interface]\n")
    normalizeWireGuardAddressList(localAddress).forEach {
        append("Address = ").append(it).append('\n')
    }
    append("PrivateKey = ").append(privateKey).append('\n')
    if (mtu > 0) append("MTU = ").append(mtu).append('\n')
    if (jc != 0) append("Jc = ").append(jc).append('\n')
    if (jmin != 0) append("Jmin = ").append(jmin).append('\n')
    if (jmax != 0) append("Jmax = ").append(jmax).append('\n')
    if (s1 != 0) append("S1 = ").append(s1).append('\n')
    if (s2 != 0) append("S2 = ").append(s2).append('\n')
    if (h1.isNotBlank()) append("H1 = ").append(h1).append('\n')
    if (h2.isNotBlank()) append("H2 = ").append(h2).append('\n')
    if (h3.isNotBlank()) append("H3 = ").append(h3).append('\n')
    if (h4.isNotBlank()) append("H4 = ").append(h4).append('\n')
    if (i1.isNotBlank()) append("I1 = ").append(i1).append('\n')
    if (i2.isNotBlank()) append("I2 = ").append(i2).append('\n')
    if (i3.isNotBlank()) append("I3 = ").append(i3).append('\n')
    if (i4.isNotBlank()) append("I4 = ").append(i4).append('\n')
    if (i5.isNotBlank()) append("I5 = ").append(i5).append('\n')
    if (s3 != 0) append("S3 = ").append(s3).append('\n')
    if (s4 != 0) append("S4 = ").append(s4).append('\n')
    if (headerProtectionKey.isNotBlank()) {
        append("HeaderProtectionKey = ").append(headerProtectionKey).append('\n')
    }
    if (contentPaddingAddition.isNotBlank()) {
        append("ContentPaddingAddition = ").append(contentPaddingAddition).append('\n')
    }
    if (rekeyAfterTime.isNotBlank()) append("RekeyAfterTime = ").append(rekeyAfterTime).append('\n')
    if (rekeyTimeout.isNotBlank()) append("RekeyTimeout = ").append(rekeyTimeout).append('\n')
    if (rejectAfterTime.isNotBlank()) append("RejectAfterTime = ").append(rejectAfterTime).append('\n')
    if (keepaliveTimeout.isNotBlank()) append("KeepaliveTimeout = ").append(keepaliveTimeout).append('\n')
    if (maxHandshakeAttempts.isNotBlank()) {
        append("MaxHandshakeAttempts = ").append(maxHandshakeAttempts).append('\n')
    }
    val isAwg31 = randomTrailers == true || disableCookies == true || isAwg31Name(name)
    if (randomTrailers == true || isAwg31) append("RandomTrailers = on\n")
    if (disableCookies == true || isAwg31) append("DisableCookies = on\n")
    append('\n')
    append("[Peer]\n")
    append("PublicKey = ").append(peerPublicKey).append('\n')
    if (peerPreSharedKey.isNotBlank()) {
        append("PresharedKey = ").append(peerPreSharedKey).append('\n')
    }
    append("Endpoint = ").append(serverAddress.wrapIPV6Host()).append(':').append(serverPort).append('\n')
    append("AllowedIPs = 0.0.0.0/0, ::/0\n")
    if (peerPersistentKeepalive.isNotBlank() && peerPersistentKeepalive != "0") {
        append("PersistentKeepalive = ").append(peerPersistentKeepalive).append('\n')
    }
    if (reserved.isNotBlank()) {
        append("Reserved = ").append(reserved).append('\n')
    }
}

fun buildSingBoxEndpointAwgBean(bean: AmneziaWGBean): SingBoxOptions.AwgEndpointOptions {
    return SingBoxOptions.AwgEndpointOptions().apply {
        type = "awg"
        address = normalizeWireGuardAddressList(bean.localAddress)
        private_key = bean.privateKey
        mtu = bean.mtu

        val peer = SingBoxOptions.AwgPeer().apply {
            address = bean.serverAddress.wrapIPV6Host()
            port = bean.serverPort
            public_key = bean.peerPublicKey
            if (bean.peerPreSharedKey.isNotBlank()) preshared_key = bean.peerPreSharedKey
            if (bean.peerPersistentKeepalive.isNotBlank() && bean.peerPersistentKeepalive != "0") {
                persistent_keepalive_interval = bean.peerPersistentKeepalive
            }
            allowed_ips = listOf("0.0.0.0/0", "::/0")
            if (bean.reserved.isNotBlank()) {
                parseReservedValues(bean.reserved.trim())?.let { reserved = it }
            }
        }
        peers = listOf(peer)

        // AWG 1.0 obfuscation parameters
        if (bean.jc != 0) jc = bean.jc
        if (bean.jmin != 0) jmin = bean.jmin
        if (bean.jmax != 0) jmax = bean.jmax
        if (bean.s1 != 0) s1 = bean.s1
        if (bean.s2 != 0) s2 = bean.s2
        if (bean.h1.isNotBlank()) h1 = bean.h1
        if (bean.h2.isNotBlank()) h2 = bean.h2
        if (bean.h3.isNotBlank()) h3 = bean.h3
        if (bean.h4.isNotBlank()) h4 = bean.h4

        // AWG 1.5 signature chain parameters
        if (bean.i1.isNotBlank()) i1 = bean.i1
        if (bean.i2.isNotBlank()) i2 = bean.i2
        if (bean.i3.isNotBlank()) i3 = bean.i3
        if (bean.i4.isNotBlank()) i4 = bean.i4
        if (bean.i5.isNotBlank()) i5 = bean.i5

        // AWG 2.0 additional packet padding parameters
        if (bean.s3 != 0) s3 = bean.s3
        if (bean.s4 != 0) s4 = bean.s4

        // AWG 3.0 parameters
        if (bean.headerProtectionKey.isNotBlank()) {
            header_protection_key = bean.headerProtectionKey
        }
        if (bean.contentPaddingAddition.isNotBlank()) {
            content_padding_addition = bean.contentPaddingAddition
        }
        if (bean.rekeyAfterTime.isNotBlank()) rekey_after_time = bean.rekeyAfterTime
        if (bean.rekeyTimeout.isNotBlank()) rekey_timeout = bean.rekeyTimeout
        if (bean.rejectAfterTime.isNotBlank()) reject_after_time = bean.rejectAfterTime
        if (bean.keepaliveTimeout.isNotBlank()) keepalive_timeout = bean.keepaliveTimeout
        if (bean.maxHandshakeAttempts.isNotBlank()) {
            max_handshake_attempts = bean.maxHandshakeAttempts
        }
        val isAwg31 = bean.randomTrailers == true || bean.disableCookies == true || isAwg31Name(bean.name) || bean.hasAmneziaWG31Options()
        if (bean.randomTrailers == true || isAwg31) random_trailers = true
        if (bean.disableCookies == true || isAwg31 || bean.randomTrailers == true) disable_cookies = true
    }
}

fun AmneziaWGBean.hasAmneziaWG31Options(): Boolean =
    randomTrailers == true || disableCookies == true || isAwg31Name(name)

fun AmneziaWGBean.hasAmneziaWG3Options(): Boolean =
    !headerProtectionKey.isNullOrBlank() ||
        !contentPaddingAddition.isNullOrBlank() ||
        !rekeyAfterTime.isNullOrBlank() ||
        !rekeyTimeout.isNullOrBlank() ||
        !rejectAfterTime.isNullOrBlank() ||
        !keepaliveTimeout.isNullOrBlank() ||
        !maxHandshakeAttempts.isNullOrBlank() ||
        peerPersistentKeepalive?.let {
            it.contains('-') || (it.toULongOrNull()?.let { value -> value > 65_535u } == true)
        } == true
