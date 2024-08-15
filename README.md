# websecuritychecker
Web Security Checker é um script Python que verifica a segurança de websites, analisando cabeçalhos HTTP, configurações TLS/SSL e vulnerabilidades comuns. Gera relatórios detalhados em formato de saída no terminal e arquivos Excel, facilitando a análise e documentação das medidas de segurança em aplicações web.

## Funcionalidades

- Verifica cabeçalhos de segurança HTTP
- Analisa configurações TLS/SSL
- Detecta uso de HTTPS
- Identifica formulários inseguros
- Gera relatórios em Excel

## Pré-requisitos

- Python 3.6+
- pip (gerenciador de pacotes Python)

## Instalação

1. Clone o repositório:
   ```
   git clone https://github.com/seu-usuario/websecuritychecker.git
   cd websecuritychecker
   ```

2. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```

## Uso

### Verificar uma única URL

```
python websecuritychecker.py https://exemplo.com
```

### Verificar múltiplas URLs de um arquivo

```
python websecuritychecker.py -l lista_de_urls.txt
```

O arquivo `lista_de_urls.txt` deve conter uma URL por linha.

## Saída

O script fornece dois tipos de saída:

1. **Saída no Terminal**: Exibe um resumo das verificações de segurança.

2. **Relatório Excel**: Gera um arquivo Excel detalhado para cada URL verificada.

### Exemplo de Saída no Terminal

```
Resultados para https://www.xyz123.com.br:

Cabeçalhos de Segurança:
  - [Vulnerável] Cache-Control: não encontrado
  - [Vulnerável] Content Security Policy não encontrado
  - [Vulnerável] Permissions-Policy: não encontrado
  - [Vulnerável] Referrer-Policy: não encontrado
  - [Vulnerável] Strict-Transport-Security: não encontrado
  - [Vulnerável] X-Content-Type-Options: não encontrado
  - [Vulnerável] X-Frame-Options: não encontrado
  - [Vulnerável] X-XSS-Protection: não encontrado

Cabeçalhos de Versão:
  - [Vulnerável] Server: Apache
  - [OK] X-AspNet-Version: não encontrado
  - [OK] X-AspNetMvc-Version: não encontrado
  - [OK] X-Powered-By: não encontrado

TLS/SSL Verificações:
  - [OK] Cipher CBC: Não usado
  - [OK] Cipher: TLS_AES_256_GCM_SHA384
  - [OK] Sweet32 Vulnerável: Não
  - [OK] Vulnerabilidade BEAST: Não

Cookies:
  - [OK] Nenhum problema encontrado com cookies

Bibliotecas JavaScript Vulneráveis:
  - [OK] Nenhuma biblioteca JavaScript vulnerável conhecida encontrada

Outras Verificações:
  - [Vulnerável] Proteção contra Clickjacking: Ausente
  - [OK] Divulgação de IP interno: Não encontrada
  - [OK] Divulgação de erro ASP.NET: Não encontrada
  - [OK] Divulgação detalhada de erros: Não encontrada
  - [OK] Mensagens de erro detalhadas: Não encontradas
  - [OK] ViewState: Não encontrado
  - [OK] Vulnerabilidade a injeções CGI: Ausente
```

### Estrutura do Relatório Excel

O arquivo Excel contém três colunas:
- **Categoria**: Tipo de verificação (Cabeçalhos de Segurança, TLS/SSL, Outras)
- **Verificação**: Nome específico da verificação
- **Resultado**: Resultado da verificação

## Personalização

Você pode adicionar ou modificar verificações editando as seguintes funções no script:

- `check_security_headers()`: Para cabeçalhos HTTP
- `check_tls_ssl()`: Para configurações TLS/SSL
- `check_security()`: Para outras verificações

## Contribuindo

Contribuições são bem-vindas! Por favor, sinta-se à vontade para submeter um Pull Request.

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

## Aviso

Este script é fornecido apenas para fins educacionais e de teste. Não use para verificar websites sem permissão explícita. O autor não se responsabiliza pelo uso indevido desta ferramenta.
