use {
    icann_rdap_common::contact::Contact,
    icann_rdap_common::prelude::{Autnum, Entity, Remark},
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_autnum_as3333_rendered_markdown_panic() {
    // GIVEN an autnum matching the RIPE NCC AS3333 structure:
    // - Many entities with vcard arrays (including nested entities)
    // - Large remarks with lines of `+` characters
    // - Multiple entities with the same handle (duplicates)
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");

    // Create nested child entities (like OPS4-RIPE has nested entities in the real data)
    let child_entities = vec![
        Entity::builder()
            .handle("ADM6699-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Andrea Di Menna")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("CNAG-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Csaba Nagy")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("MENN1-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Menno Schepers")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("RCO-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Razvan C. Oprea")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("RDM397-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Rob de Meester")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("SG16480-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Saloumeh Ghasemi")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("SO2011-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Sjoerd Oostdijck")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("TIB-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Timur I Bakeyev")
                    .build(),
            )
            .build(),
        Entity::builder()
            .handle("TOL666-RIPE")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("Marco van Tol")
                    .build(),
            )
            .build(),
    ];

    // Create the parent entity with nested children (like OPS4-RIPE in the real data)
    let ops4_entity = Entity::builder()
        .handle("OPS4-RIPE")
        .contact(
            Contact::builder()
                .kind("group")
                .full_name("RIPE NCC Operations")
                .build(),
        )
        .role("technical")
        .entities(child_entities)
        .build();

    // Create top-level entities (matching the RIPE NCC AS3333 structure)
    let top_level_entities = vec![
        Entity::builder()
            .handle("MDIR-RIPE")
            .contact(
                Contact::builder()
                    .kind("group")
                    .full_name("Managing Director")
                    .build(),
            )
            .role("administrative")
            .build(),
        ops4_entity,
        Entity::builder()
            .handle("ORG-RIEN1-RIPE")
            .contact(
                Contact::builder()
                    .kind("org")
                    .full_name("Reseaux IP Europeens Network Coordination Centre (RIPE NCC)")
                    .build(),
            )
            .role("registrant")
            .build(),
        Entity::builder()
            .handle("RIPE-NCC-END-MNT")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("RIPE-NCC-END-MNT")
                    .build(),
            )
            .role("registrant")
            .build(),
        Entity::builder()
            .handle("RIPE-NCC-MNT")
            .contact(
                Contact::builder()
                    .kind("individual")
                    .full_name("RIPE-NCC-MNT")
                    .build(),
            )
            .role("registrant")
            .build(),
    ];

    // Create a large remark with `+` characters (matching the RIPE NCC AS3333 data)
    let ripe_peering_remark = Remark::builder()
        .title("Peering Information")
        .description_entry("Reseaux IP Europeens Network Coordination Centre (RIPE NCC)")
        .description_entry("")
        .description_entry("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        .description_entry("| AS3333 RIPE-NCC-AS |")
        .description_entry("| RIPE NCC (Network Coordination Centre) |")
        .description_entry("| |")
        .description_entry("| RIPE NCC (AS3333) operates an open peering policy: |")
        .description_entry("| We advertise only routes from AS-RIPENCC |")
        .description_entry("| We will accept any routes offered including TRANSIT! |")
        .description_entry("| We will update our aut-num object in the RIPE Whois |")
        .description_entry("| Database and kindly request you to update yours |")
        .description_entry("| We would prefer not to enter into a peering contract |")
        .description_entry("| In the event of problems due to leaked advertisements |")
        .description_entry("| it is our policy to shut down peerings and ask |")
        .description_entry("| questions later. |")
        .description_entry("| We may tag our announcements with the NO_EXPORT or |")
        .description_entry("| other communities, please honour these if set. |")
        .description_entry("| * AMS-IX - IPv4 * |")
        .description_entry("| 80.249.208.68 - Equinix AM3 |")
        .description_entry("| 80.249.208.71 - Telecity AMS5 |")
        .description_entry("| * AMS-IX - IPv6 * |")
        .description_entry("| 2001:7F8:1::A500:3333:1 - Equinix AM3 |")
        .description_entry("| 2001:7F8:1::A500:3333:2 - Telecity AMS5 |")
        .description_entry("| Telephone: +31 20 535 4444 |")
        .description_entry("| Fax: +31 20 535 4445 |")
        .description_entry("| Abuse: abuse@ripe.net |")
        .description_entry("| Peering: peering@ripe.net |")
        .description_entry("| Operations/NOC: ops@ripe.net |")
        .description_entry("| Info: https://www.ripe.net/ |")
        .description_entry("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        .description_entry("| PRIVATE-TRANSIT-V4 |")
        .description_entry("| Private transit peering |")
        .description_entry("| TeliaSonera |")
        .description_entry("| AMS-IX-TRANSIT |")
        .description_entry("| SURFnet |")
        .description_entry("| KPN Wholesale Service & Op. (AS1136) |")
        .description_entry("| Tele2 Sverige AB |")
        .description_entry("| Cable & Wireless Netherlands B.V. |")
        .description_entry("| BIT |")
        .description_entry("| KPN Wholesale Service & Op. (AS286) |")
        .description_entry("| AMS-IX-LARGE |")
        .description_entry("| AMS-IX BGP4 Peers with a LARGE number of prefixes |")
        .description_entry("| Tiscali |")
        .description_entry("| Deutsche Telekom AG |")
        .description_entry("| Telecom Italia Sparkle |")
        .description_entry("| Hurricane Electric |")
        .description_entry("| AMS-IX-MEDIUM |")
        .description_entry("| Verizon Business, NIKHEF, peering@verizonbusiness.com |")
        .description_entry("| iNES Group |")
        .description_entry("| Highwinds Network Group Inc. |")
        .description_entry("| Lambdanet Communications Deutschland AG |")
        .description_entry("| Open Peering |")
        .description_entry("| PJSC Datagroup |")
        .description_entry("| ISPRIME B.V. |")
        .description_entry("| NORDUnet A/S |")
        .description_entry("| Arcor AG & Co |")
        .description_entry("| State Institute of Information Technologies and Telecommunications |")
        .description_entry("| TDC A/S |")
        .description_entry("| Swisscom AG |")
        .description_entry("| Neterra Ltd. |")
        .description_entry("| Anders Business Group Ltd. |")
        .description_entry("| IPTP Networks |")
        .description_entry("| W-IX |")
        .description_entry("| BT |")
        .description_entry("| Atrato IP Networks |")
        .description_entry("| Belgacom International Carrier Services SA |")
        .description_entry("| UPC Broadband Operations |")
        .description_entry("| Verizon Business |")
        .description_entry("| Colt Telecom Group |")
        .description_entry("| COMSTAR-Direct CJSC |")
        .description_entry("| RETN Ltd. |")
        .description_entry("| AMS-IX-SMALL |")
        .description_entry("| Alsatis, AMS-IX, peering@alsatis.com |")
        .description_entry("| RIPE NCC (AS112 Project) |")
        .description_entry("| SARA |")
        .description_entry("| SIDN Stichting Internet Domeinregistratie NL |")
        .description_entry("| Amsterdam Internet Exchange (rtr-eun-01) |")
        .description_entry("| Plus.line AG |")
        .description_entry("| ScanPlus GmbH |")
        .description_entry("| Solcon Internetdiensten B.V. |")
        .description_entry("| IDnet (IDnet) |")
        .description_entry("| SOCO Network Solutions GmbH |")
        .description_entry("| ITGate |")
        .description_entry("| Concepts ICT Holding B.V. |")
        .description_entry("| Luna.nl |")
        .description_entry("| TNG - The Net Generation AG |")
        .description_entry("| Tele2 Nederland B.V. |")
        .description_entry("| EdgeCast Network |")
        .description_entry("| NedLook internet solutions |")
        .description_entry("| CAIW Netwerken BV |")
        .description_entry("| ZeelandNet BV |")
        .description_entry("| Virtu Secure Webservices BV |")
        .description_entry("| Leaseweb |")
        .description_entry("| OVH |")
        .description_entry("| InterBox Internet |")
        .description_entry("| Amazon.com |")
        .description_entry("| Green.ch AG |")
        .description_entry("| RIPE NCC Auth DNS Cluster |")
        .description_entry("| We Dare B.V. |")
        .description_entry("| Titan Networks GmbH |")
        .description_entry("| Previder B.V. |")
        .description_entry("| Blatzheim Networks Telecom GmbH |")
        .description_entry("| SIG/IP- MAN |")
        .description_entry("| Akamai International B.V. |")
        .description_entry("| Info.nl |")
        .description_entry("| Telenor |")
        .description_entry("| InfoPact Netwerkdiensten B.V. |")
        .description_entry("| Plex Elektronische Informatie BV |")
        .description_entry("| Limelight Networks |")
        .description_entry("| ASGCNet (Academia Sinica Grid Computing Network Taiwan) (ASNet) |")
        .description_entry("| Intermax BV |")
        .description_entry("| Caveo Internet B.V. |")
        .description_entry("| ISP Services |")
        .description_entry("| Hetzner Online AG |")
        .description_entry("| INET-People Provider Services |")
        .description_entry("| Basefarm |")
        .description_entry("| Cyso Managed Hosting |")
        .description_entry("| RIPE NCC (K-root server) |")
        .description_entry("| Denit Internet Services |")
        .description_entry("| BELNET |")
        .description_entry("| AT&T Global Network Services |")
        .description_entry("| Unilogic Networks B.V. |")
        .description_entry("| Aire Networks |")
        .description_entry("| Dial Telecom a.s. |")
        .description_entry("| Gemeente Den Haag |")
        .description_entry("| UNET BV |")
        .description_entry("| Momax S.r.l. |")
        .description_entry("| Internet Systems Consortium (F-Root) |")
        .description_entry("| Exa Networks |")
        .description_entry("| Waycom |")
        .description_entry("| SpeedXS |")
        .description_entry("| Serbia BroadBand |")
        .description_entry("| BSO Communication |")
        .description_entry("| Duocast |")
        .description_entry("| Sarenet |")
        .description_entry("| XS4ALL Internet |")
        .description_entry("| Kantonsschule Zug |")
        .description_entry("| Base IP BV |")
        .description_entry("| Lottomatica SpA |")
        .description_entry("| Packet Clearing House |")
        .description_entry("| Convergenze S.p.a. |")
        .description_entry("| OpenCarrier e.G. |")
        .description_entry("| Jansen Systemberatung GmbH |")
        .description_entry("| GlobalConnect |")
        .description_entry("| Wikimedia Foundation Inc. |")
        .description_entry("| Easynet Limited |")
        .description_entry("| Motto VoIP |")
        .description_entry("| I3D |")
        .description_entry("| Online Breedband BV |")
        .description_entry("| Vialtus Solutions |")
        .description_entry("| Breedband Nederland B.V. |")
        .description_entry("| ANO Russian Institute for Public Networks (RIPN) |")
        .description_entry("| Orange Business Services |")
        .description_entry("| Green ISP B.V. |")
        .description_entry("| EUnet Finland (Saunalahti Group Oyj) |")
        .description_entry("| www.strato.de |")
        .description_entry("| TDC Switzerland AG |")
        .description_entry("| Telefonica Deutschland GmbH |")
        .description_entry("| Verisign |")
        .description_entry("| MANDA |")
        .description_entry("| Claranet Benelux |")
        .description_entry("| Telekom Austria |")
        .description_entry("| 1&1 Internet AG |")
        .description_entry("| XB Networks |")
        .description_entry("| Coolwave Communications BV |")
        .description_entry("| Ziggo bv |")
        .description_entry("| InterConnect Services B.V. |")
        .description_entry("| AMS-IX-V6-TRANSIT |")
        .description_entry("| AMS-IX BGP6 Peers who pass us a FULL routing table |")
        .description_entry("| AMS-IX-V6 |")
        .description_entry("| FreeSAS |")
        .description_entry("| Google |")
        .description_entry("| IntroWeb Nederland B.V. |")
        .description_entry("| xo.com |")
        .description_entry("| NTT Communications Global IP Network |")
        .description_entry("| Computel Standby BV |")
        .description_entry("| tele.dk |")
        .description_entry("| Seabone.net |")
        .description_entry("| EspritXB B.V. |")
        .description_entry("| Portugal Telecom Comunicacoes SA (IPv6) |")
        .description_entry("| AMS-IX-COLLECTORS |")
        .description_entry("| AMS-IX Route Collectors - Give all, get nothing |")
        .description_entry("| Renesys Corp |")
        .description_entry("| COLLECTORS |")
        .description_entry("| Route Collectors - Give all, get nothing |")
        .description_entry("| RIS Project |")
        .description_entry("| <Oregon Exchange BGP Router Viewer |")
        .description_entry("| ISOLARIO - Istituto Italiano di Telematica CNR Pisa |")
        .description_entry("| COLLECTORS-V6 |")
        .description_entry("| Route Collectors (IPv6) - Give all, get nothing |")
        .description_entry("| AMS-IX Route Servers |")
        .description_entry("| RIS Transit |")
        .build();

    tx.add_autnum(
        &Autnum::response_obj()
            .autnum_range(3333..3334)
            .handle("AS3333")
            .name("RIPE-NCC-AS")
            .status("active")
            .entities(top_level_entities)
            .remark(ripe_peering_remark)
            .build(),
    )
    .await
    .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rendered-markdown output type
    test_jig.cmd.arg("3333").arg("-O").arg("rendered-markdown");

    // THEN this should panic (the panic is expected and will be caught by the test framework)
    test_jig.cmd.assert().failure();
}
