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
   git clone https://github.com/seu-usuario/web-security-checker.git
   cd web-security-checker
   ```

2. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```

## Uso

### Verificar uma única URL

```
python security_checker.py https://exemplo.com
```

### Verificar múltiplas URLs de um arquivo

```
python security_checker.py -l lista_de_urls.txt
```

O arquivo `lista_de_urls.txt` deve conter uma URL por linha.

## Saída

O script fornece dois tipos de saída:

1. **Saída no Terminal**: Exibe um resumo das verificações de segurança.

2. **Relatório Excel**: Gera um arquivo Excel detalhado para cada URL verificada.

### Exemplo de Saída no Terminal

```
Verificando https://exemplo.com

Cabeçalhos de Segurança:
  Strict-Transport-Security: max-age=31536000
  X-Frame-Options: SAMEORIGIN
  ...

TLS/SSL Verificações:
  Modo CBC: Não usado
  Cipher Suite: ECDHE-RSA-AES256-GCM-SHA384
  Protocolo TLS: TLSv1.3
  ...

Outras Verificações:
  HTTPS: Sim
  Formulários Inseguros: Não

Relatório gerado: relatorio_seguranca_exemplo.com.xlsx
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
