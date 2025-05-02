# Port Scanner - Docker Kurulumu

Bu dokümantasyon, Port Scanner uygulamasını Docker ortamında çalıştırmak için gerekli adımları içerir.

## Gereksinimler

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Kurulum

1. Proje dizinine gidin:

```bash
cd /path/to/PortScanner
```

2. Docker Compose ile servisleri başlatın:

```bash
docker-compose up -d
```

Bu komut aşağıdaki servisleri başlatacaktır:
- Web uygulaması (Flask)
- PostgreSQL veritabanı
- Redis
- Celery worker
- Celery beat (zamanlanmış görevler için)

3. Uygulamaya erişim:

Uygulama şu adreste erişilebilir olacaktır:
```
http://localhost:5000
```

Varsayılan kullanıcı bilgileri:
- Kullanıcı adı: admin
- Şifre: admin

## Servis Durumunu Kontrol Etme

Tüm servislerin durumunu görmek için:

```bash
docker-compose ps
```

## Log Dosyalarını İzleme

Herhangi bir servisin log'larını görmek için:

```bash
docker-compose logs -f web          # Web uygulaması logları
docker-compose logs -f db           # PostgreSQL logları
docker-compose logs -f redis        # Redis logları
docker-compose logs -f celery-worker # Celery worker logları
docker-compose logs -f celery-beat  # Celery beat logları
```

## Servisleri Durdurma

Tüm servisleri durdurmak için:

```bash
docker-compose down
```

Veritabanını da kaldırmak için:

```bash
docker-compose down -v
```

## Veritabanı Yönetimi

Veritabanına bağlanmak için:

```bash
docker-compose exec db psql -U postgres -d portscanner
```

## Sorun Giderme

### Uygulama Başlatılamıyor

1. Log dosyalarını kontrol edin:
```bash
docker-compose logs -f web
```

2. Veritabanı bağlantısını kontrol edin:
```bash
docker-compose exec web python -c "from app import db; print(db.engine.connect())"
```

3. Celery bağlantısını kontrol edin:
```bash
docker-compose exec celery-worker celery -A app.tasks.celery status
```

### Değişiklikler Uygulanmıyor

Değişiklikler yaptıktan sonra servisleri yeniden başlatın:

```bash
docker-compose restart web
```

Veya tüm servisleri yeniden oluşturun:

```bash
docker-compose up -d --build
```

## Güvenlik Notları

Üretim ortamında dağıtmadan önce:

1. docker-compose.yml dosyasında SECRET_KEY değerini değiştirin
2. Veritabanı şifrelerini değiştirin
3. Varsayılan admin kullanıcısının şifresini değiştirin
4. Güvenlik duvarı kurallarını yapılandırın 