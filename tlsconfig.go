package main

import "crypto/tls"

// insecureTLSConfig возвращает TLS-конфигурацию с отключённой проверкой
// сертификата. Это осознанное решение, а не забытый долг: инструмент
// анализирует, КАК блокируется соединение (RST, DPI-фрагментация, SNI-фильтрация
// и т.д.), а не проверяет легитимность сертификата целевого хоста — валидный
// сертификат тут не требуется и часто мешает диагностике MITM/блокировок.
// Собран в одном месте, чтобы `go vet`/линтеры не ругались на каждое
// InsecureSkipVerify по отдельности и чтобы при необходимости было проще
// централизованно добавить allowlist или иные меры.
func insecureTLSConfig(nextProtos ...string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // required for censorship analysis, see doc comment above
		NextProtos:         nextProtos,
	}
}
