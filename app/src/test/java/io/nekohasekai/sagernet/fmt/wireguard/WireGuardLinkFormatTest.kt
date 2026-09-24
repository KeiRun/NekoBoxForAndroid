package io.nekohasekai.sagernet.fmt.wireguard

import io.nekohasekai.sagernet.group.RawUpdater
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class WireGuardLinkFormatTest {
    @Test
    fun throneWireGuardLinkRoundTrips() {
        val bean = WireGuardBean().apply {
            initializeDefaultValues()
            name = "WG Europe"
            serverAddress = "2001:db8::1"
            serverPort = 51820
            privateKey = "private+/="
            peerPublicKey = "public+/="
            peerPreSharedKey = "psk+/="
            localAddress = "10.0.0.2/32\nfd00::2/128"
            mtu = 1380
            reserved = "0, 2, 255"
            peerPersistentKeepalive = 25
        }

        val link = bean.toWireGuardUri()
        val parsed = parseThroneWireGuardUri(link) as WireGuardBean

        assertTrue(link.startsWith("wg://[2001:db8::1]:51820?"))
        assertEquals(bean.name, parsed.name)
        assertEquals(bean.serverAddress, parsed.serverAddress)
        assertEquals(bean.serverPort, parsed.serverPort)
        assertEquals(bean.privateKey, parsed.privateKey)
        assertEquals(bean.peerPublicKey, parsed.peerPublicKey)
        assertEquals(bean.peerPreSharedKey, parsed.peerPreSharedKey)
        assertEquals(bean.localAddress, parsed.localAddress)
        assertEquals(bean.mtu, parsed.mtu)
        assertEquals("0,2,255", parsed.reserved)
        assertEquals(bean.peerPersistentKeepalive, parsed.peerPersistentKeepalive)
    }

    @Test
    fun throneAmneziaParametersCreateAmneziaProfile() {
        val parsed = parseThroneWireGuardUri(
            "wireguard://example.com:51820" +
                "?private_key=private&peer_public_key=public&local_address=10.0.0.2%2F32" +
                "&enable_amnezia=true&jc=4&i1=%3Cb%200x01%3E&rekey_after_time=10-20" +
                "&random_trailers=on&disable_cookies=enabled",
        ) as AmneziaWGBean

        assertEquals(4, parsed.jc)
        assertEquals("<b 0x01>", parsed.i1)
        assertEquals("10-20", parsed.rekeyAfterTime)
        assertTrue(parsed.randomTrailers)
        assertTrue(parsed.disableCookies)
    }

    @Test
    fun throneQueryKeepsLiteralPlusSigns() {
        val parsed = parseThroneWireGuardUri(
            "wg://example.com:51820" +
                "?private_key=private+key=&public_key=public+key=" +
                "&pre_shared_key=shared+key=&local_address=10.0.0.2%2F32",
        ) as WireGuardBean

        assertEquals("private+key=", parsed.privateKey)
        assertEquals("public+key=", parsed.peerPublicKey)
        assertEquals("shared+key=", parsed.peerPreSharedKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun throneLinkRequiresExplicitPort() {
        parseThroneWireGuardUri(
            "wg://example.com?private_key=private&public_key=public",
        )
    }

    @Test
    fun amneziaLineAliasesImportAndCanonicalExport() = runBlocking {
        val config = amneziaConfig("server.example.com")
        val encoded = encode(config)
        val profiles = RawUpdater.parseRaw(
            "awg://$encoded#Netherlands\namneziawg://$encoded#Duplicate",
        ).orEmpty()

        assertEquals(1, profiles.size)
        val bean = profiles.single() as AmneziaWGBean
        assertEquals("Netherlands", bean.name)
        assertTrue(bean.toAmneziaWGUri().startsWith("amneziawg://"))
        assertTrue(bean.toAmneziaWGUri().endsWith("#Netherlands"))
    }

    @Test
    fun jsonContainerSkipsBadEntriesAndUsesNameFallbacks() {
        val namedConfig = "# Name=Comment Name\n${amneziaConfig("one.example")}"
        val json = JSONObject(
            """
            {
              "type": "amneziawg",
              "version": 99,
              "servers": [
                {"name": "Explicit", "config": "${encode(amneziaConfig("explicit.example"))}"},
                {"config": "${encode(namedConfig)}"},
                {"config": "%%%"}
              ]
            }
            """.trimIndent(),
        )

        val profiles = parseAmneziaWGJsonContainer(json)

        assertEquals(listOf("Explicit", "Comment Name"), profiles.map { it.name })
        val exported = JSONObject(buildAmneziaWGJsonContainer(profiles))
        assertEquals("amneziawg", exported.getString("type"))
        assertEquals(1, exported.getInt("version"))
        assertEquals(2, exported.getJSONArray("servers").length())
    }

    @Test
    fun awg3OptionsRoundTripThroughExistingExports() {
        val bean = AmneziaWGBean().apply {
            initializeDefaultValues()
            name = "AWG 3.1"
            serverAddress = "awg.example.com"
            serverPort = 51820
            localAddress = "10.0.0.2/32"
            privateKey = "private"
            peerPublicKey = "public"
            headerProtectionKey = "header-key"
            contentPaddingAddition = "10-100"
            rekeyAfterTime = "100-120"
            rekeyTimeout = "3-7"
            rejectAfterTime = "150-180"
            keepaliveTimeout = "5-15"
            maxHandshakeAttempts = "15-20"
            randomTrailers = true
            disableCookies = true
        }

        val fromLink = parseAmneziaWGUri(bean.toAmneziaWGUri()).single()
        val fromJson = parseAmneziaWGJsonContainer(
            JSONObject(buildAmneziaWGJsonContainer(listOf(bean))),
        ).single()

        listOf(fromLink, fromJson).forEach { parsed ->
            assertEquals("header-key", parsed.headerProtectionKey)
            assertEquals("10-100", parsed.contentPaddingAddition)
            assertEquals("100-120", parsed.rekeyAfterTime)
            assertEquals("3-7", parsed.rekeyTimeout)
            assertEquals("150-180", parsed.rejectAfterTime)
            assertEquals("5-15", parsed.keepaliveTimeout)
            assertEquals("15-20", parsed.maxHandshakeAttempts)
            assertTrue(parsed.randomTrailers)
            assertTrue(parsed.disableCookies)
        }
    }

    private fun amneziaConfig(host: String) =
        """
        [Interface]
        PrivateKey = private
        Address = 10.0.0.2/32
        Jc = 4
        Jmin = 40
        Jmax = 70
        S1 = 11
        S2 = 12
        H1 = 101
        H2 = 102

        [Peer]
        PublicKey = public
        Endpoint = $host:51820
        """.trimIndent()

    @Test
    fun standardAmneziaWGUriParsesSuccessfully() {
        val uri = "amneziawg://wGy%2Bb1LLyhYtnz68v22m2jbixxyX5mls55jx7r20hUY%3D@77.239.109.87:49642?address=10.7.0.2%2F32&contentpaddingaddition=58-106&dns=1.1.1.1&headerprotectionkey=aaHBGi5rQCR%2FL4BUXXg03i4fT0cOakphMEtkMqOhqDw%3D&jc=11&jmax=116&jmin=29&keepalive=15-25&keepalivetimeout=11-18&maxhandshakeattempts=13-18&mtu=1360&presharedkey=1010101010101010101010101010101010101010101%3D&publickey=gG03xNqX8i0m1Hq0L5KqT60k02qQ22b0s1kQ614n22M%3D&randomtrailers=true&disablecookies=true&rejectaftertime=120-165&rekeyaftertime=120-165&rekeytimeout=5-6&s1=113&s2=117&s3=115&s4=116#NL2-Awg3.1-ss4-main"
        val beans = parseAmneziaWGUri(uri)
        assertEquals(1, beans.size)
        val bean = beans.single()
        assertEquals("NL2-Awg3.1-ss4-main", bean.name)
        assertEquals("77.239.109.87", bean.serverAddress)
        assertEquals(49642, bean.serverPort)
        assertEquals("wGy+b1LLyhYtnz68v22m2jbixxyX5mls55jx7r20hUY=", bean.privateKey)
        assertEquals("gG03xNqX8i0m1Hq0L5KqT60k02qQ22b0s1kQ614n22M=", bean.peerPublicKey)
        assertEquals("1010101010101010101010101010101010101010101=", bean.peerPreSharedKey)
        assertEquals("15-25", bean.peerPersistentKeepalive)
        assertEquals("58-106", bean.contentPaddingAddition)
        assertEquals(true, bean.randomTrailers)
        assertEquals(true, bean.disableCookies)
        assertTrue(bean.hasAmneziaWG31Options())
    }

    @Test
    fun commentOnFirstLineIdentifiesProfileName() {
        val conf = """
            # NL2-Awg3.1-ss4-main
            [Interface]
            PrivateKey = private
            Address = 10.0.0.2/32
            [Peer]
            PublicKey = public
            Endpoint = 1.2.3.4:51820
        """.trimIndent()
        val beans = RawUpdater.parseAmneziaWG(conf)
        assertEquals("NL2-Awg3.1-ss4-main", beans.single().name)
    }

    @Test
    fun awg31ProfileNameAutoEnablesTrailersAndDisablesCookies() {
        val uriWithoutParams = "amneziawg://wGy%2Bb1LLyhYtnz68v22m2jbixxyX5mls55jx7r20hUY%3D@77.239.109.87:49642?address=10.7.0.2%2F32&publickey=gG03xNqX8i0m1Hq0L5KqT60k02qQ22b0s1kQ614n22M%3D&headerprotectionkey=test#NL2-Awg3.1-ss4-main"
        val beans = parseAmneziaWGUri(uriWithoutParams)
        val bean = beans.single()
        assertEquals("NL2-Awg3.1-ss4-main", bean.name)
        assertTrue(bean.randomTrailers == true)
        assertTrue(bean.disableCookies == true)
        assertTrue(bean.hasAmneziaWG31Options())

        val sbEndpoint = buildSingBoxEndpointAwgBean(bean)
        assertTrue(sbEndpoint.random_trailers == true)
        assertTrue(sbEndpoint.disable_cookies == true)
    }

    @Test
    fun awg31TrailerAliasesAndAutoDisableCookies() {
        val uriWithRt = "amneziawg://wGy%2Bb1LLyhYtnz68v22m2jbixxyX5mls55jx7r20hUY%3D@77.239.109.87:49642?address=10.7.0.2%2F32&publickey=gG03xNqX8i0m1Hq0L5KqT60k02qQ22b0s1kQ614n22M%3D&rt=true#NL1"
        val bean = parseAmneziaWGUri(uriWithRt).single()
        assertTrue(bean.randomTrailers == true)
        assertTrue(bean.disableCookies == true)

        val uriWithTrailers = "amneziawg://wGy%2Bb1LLyhYtnz68v22m2jbixxyX5mls55jx7r20hUY%3D@77.239.109.87:49642?address=10.7.0.2%2F32&publickey=gG03xNqX8i0m1Hq0L5KqT60k02qQ22b0s1kQ614n22M%3D&trailers=1#NL1"
        val bean2 = parseAmneziaWGUri(uriWithTrailers).single()
        assertTrue(bean2.randomTrailers == true)
        assertTrue(bean2.disableCookies == true)
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encode(value: String): String =
        Base64.UrlSafe.encode(value.toByteArray()).trimEnd('=')
}
