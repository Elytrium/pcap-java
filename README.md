<img src="https://elytrium.net/src/img/elytrium.webp" alt="Elytrium" align="right">

# pcap-java

[![Join our Discord](https://img.shields.io/discord/775778822334709780.svg?logo=discord&label=Discord)](https://ely.su/discord)

Lightweight libpcap Java (JNI) wrapper.

## Why pcap-java?

- pcap-java uses JNI to interact with the native stuff, while other libraries use JNA.

## How to

Sample code:

```java
    Pcap.init();
    PcapHandle handle = Pcap.openLive("any", 120, 1, 10);
    PcapDumper dumper = handle.dumpOpen("dump.pcap");
    BpfProgram filter = handle.compile("tcp and dst port 80");
    handle.setFilter(filter);
    filter.free();

    LinkType datalink = this.handle.datalink();
    new Thread(() -> {
        try {
            this.handle.loop(-1, (packetHeader, rawPacket) -> {
                try {
                    Packet packet = new Packet();
                    packet.decode(rawPacket, datalink);
                    System.out.println(packet);
                    dumper.dump(packetHeader, rawPacket);
                    dumper.flush();
                } catch (LayerDecodeException | PcapException e) {
                    e.printStackTrace();
                }
            });
        } catch (PcapException e) {
        e.printStackTrace();
        }
    });
    
    dumper.close();
    handle.close();
```

## How to include it

#### Setup your project via adding our maven repository to your pom.xml or build.gradle file.

- Maven:

```xml
    <repositories>
        <repository>
            <id>elytrium-repo</id>
            <url>https://maven.elytrium.net/repo/</url>
        </repository>
    </repositories>

    <dependencies>
        <dependency>
            <groupId>net.elytrium</groupId>
            <artifactId>pcap</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
```

- Gradle:

```groovy
    repositories {
        maven {
            setName("elytrium-repo")
            setUrl("https://maven.elytrium.net/repo/")
        }
    }

    dependencies {
        implementation("net.elytrium:pcap:1.0.0")
    }
```

## See also

- [LimboFilter TCP Listener](https://github.com/Elytrium/LimboFilter/blob/master/src/main/java/net/elytrium/limbofilter/listener/TcpListener.java) - Another code example.

## Donation

Your donations are really appreciated. Donations wallets/links/cards:

- MasterCard Debit Card (Tinkoff Bank): ``5536 9140 0599 1975``
- Qiwi Wallet: ``PFORG`` or [this link](https://my.qiwi.com/form/Petr-YSpyiLt9c6)
- YooMoney Wallet: ``4100 1721 8467 044`` or [this link](https://yoomoney.ru/quickpay/shop-widget?writer=seller&targets=Donation&targets-hint=&default-sum=&button-text=11&payment-type-choice=on&mobile-payment-type-choice=on&hint=&successURL=&quickpay=shop&account=410017218467044)
- Monero (XMR): 86VQyCz68ApebfFgrzRFAuYLdvd3qG8iT9RHcru9moQkJR9W2Q89Gt3ecFQcFu6wncGwGJsMS9E8Bfr9brztBNbX7Q2rfYS
