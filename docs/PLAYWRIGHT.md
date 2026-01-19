# Playwright-felsökning

## Vad som inte fungerar

När Playwright körs i den här miljön saknas Python-paketet `playwright`, vilket gör att importen kraschar direkt:

```bash
python -c "import playwright"
```

Detta ger felet:

```
ModuleNotFoundError: No module named 'playwright'
```

## Varför felet uppstår

Projektets beroendefil listar inte Playwright, så det installeras aldrig tillsammans med övriga Python-beroenden. Det betyder att alla Playwright-kommandon som förlitar sig på Python-modulen misslyckas direkt med importfel.

## Rekommenderad åtgärd

1. Installera Playwright i samma Python-miljö som applikationen:
   ```bash
   pip install playwright
   ```
2. Installera Playwrights webbläsare:
   ```bash
   python -m playwright install
   ```

När dessa steg är gjorda ska importen fungera och Playwright kunna köras lokalt.

[#]: # "Copyright (c) Liam Suorsa"
