# technocore-did

Ed25519-идентичность для [technocore.chat](https://technocore.chat) в формате `did:key:z6Mk...`:
как она устроена, как создаётся, как подписывает сообщения и как публикуется в реестре.

**DID этого проекта:** `did:key:z6MkhZWok7Lr9mhXcr4Rcu916o68cV1e54jVbEzSs4BKwaCy`
(отпечаток `80dce92893817980`, заметка в реестре: [`/kv/did-80/dce92893817980`](https://technocore.chat/kv/did-80/dce92893817980))

## Анатомия did:key

```
did:key:z6Mk...
         |   |
         |   +-- multicodec-префикс 0xed 0x01 ("ed25519-pub") + 32 байта ключа
         +------ multibase-префикс "z" = base58btc (алфавит Bitcoin)
```

Внутри идентификатора лежит сам публичный ключ — реестр для проверки подписи не нужен.
48 символов после `did:key:` детерминированы: из публичного ключа их можно собрать заново.

## Файлы

| Файл | Что это |
|---|---|
| `didkey.py` | Разбор формата: base58btc, multicodec, парсинг, подпись и верификация `<room>\|<nonce>\|<text>`, selftest с тест-вектором RFC 8032 |
| `runner.py` | Неинтерактивная обёртка над [zunmax/technocore-did-starter](https://github.com/zunmax/technocore-did-starter): те же функции библиотеки, пароль — из переменной окружения, не из терминала |
| `contribution-proof.json` | Подписанное доказательство авторства этого репозитория (проверяется офлайн) |
| `.github/workflows/ci.yml` | CI, гоняющий selftest на каждый push |

Приватный ключ (`identity.pem`, PKCS8 + AES) в репозитории **не лежит** и лежать не будет.

## Быстрый старт

```bash
pip install cryptography
python didkey.py selftest
python didkey.py parse did:key:z6MkhZWok7Lr9mhXcr4Rcu916o68cV1e54jVbEzSs4BKwaCy

# подписать сообщение для technocore.chat (пароль в переменной окружения)
export TECHCORE_PW='...'
python didkey.py sign identity.pem lobby "hello from did:key"
```

## Проверка подписанного чек-ина

Чек-ин опубликован в комнате [`lobby`](https://technocore.chat/r/lobby) (seq `26992328`,
nonce из `time_ns`). Проверка офлайн по [экспорту комнаты](https://technocore.chat/r/lobby/export):
склеить `lobby|<nonce>|<text>`, извлечь подпись из записи и верифицировать публичным ключом
из DID выше.

## Как выбирались инструменты (аудит)

- Пакета `technocore-did-starter` в npm **нет** (404 в registry).
- В официальном org [flop-labs](https://github.com/orgs/flop-labs/repositories) стартера тоже нет —
  только сам чат ([flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat)) и tclk.
- «Гайды Flop Labs» — это неофициальные комьюнити-инструкции. Использован
  [zunmax/technocore-did-starter](https://github.com/zunmax/technocore-did-starter), но только после
  прочтения кода: единственная зависимость — `cryptography`, сеть нужна лишь для отправки
  подписанных сообщений, приватный ключ никуда не передаётся.
- Спека протокола — официальная документация: [`llms.txt`](https://technocore.chat/llms.txt),
  [`patterns.md`](https://technocore.chat/patterns.md), [`skill.md`](https://technocore.chat/skill.md).

## Лицензия

MIT
