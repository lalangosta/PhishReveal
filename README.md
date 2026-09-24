# PhishReveal

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-Automation-green.svg)
![Security](https://img.shields.io/badge/Security-Phishing_Analysis-red.svg)

PhishReveal és una eina que he desenvolupat en Python per automatitzar el triatge i l'anàlisi de correus sospitosos de phishing. La idea se'm va acudir durant les meves pràctiques a la Generalitat de Catalunya, on vèiem contínuament correus d'aquest estil que intentaven robar credencials utilitzant webs creades amb plataformes com Google Sites o Canva per saltar-se els filtres de seguretat habituals.

El sistema agafa els correus reportats, en treu els enllaços i utilitza navegació automatitzada en segon pla per comprovar si realment amaguen formularis de robatori de contrasenyes sota serveis legítims. L'objectiu és estalviar feina manual als equips de seguretat i poder respondre a aquests atacs molt més ràpid.

## Descripció del Projecte

El sistema automatitza el flux de validació d'enllaços maliciosos:
- **Ingesta i Parsing:** Processament natiu d'arxius `.eml` per extreure'n les metadades (remitent, assumpte) i el cos del missatge (HTML/Text).
- **Extracció d'IoC:** Identificació d'URLs mitjançant expressions regulars i anàlisi de l'arbre DOM.
- **Motor Heurístic i d'Inspecció Dinàmica:** Ús de **Playwright** per obrir els enllaços sospitosos en un sandbox, buscant automàticament camps `<input type="password">` i generant evidències gràfiques (captures de pantalla).

## Arquitectura i Flux de Treball

1. **Input:** L'usuari o sistema passa un fitxer de correu (`.eml`).
2. **Fase 1 (Estàtica):** Extracció de totes les URLs. Filtrant per llistes de dominis freqüentment utilitzats (ex. `sites.google.com`).
3. **Fase 2 (Dinàmica):** Si la URL coincideix amb un domini de risc, PhishReveal llança una instància de Chromium en mode *headless*. Renderitza la pàgina (esperant càrregues asíncrones) i inspecciona l'HTML resultant buscant formularis d'autenticació no autoritzats.
4. **Output:** Generació d'un fitxer JSON amb la intel·ligència de l'amenaça (Threat Intel) i captures de pantalla del lloc maliciós.

## Instal·lació i Execució

### Requisits

- Python 3.8 o superior.
- Les llibreries pertinents detallades a continuació.

### Passos per configurar l'entorn

1. Clonar aquest repositori:
   ```bash
   git clone https://github.com/lalangosta/PhishReveal.git
   cd PhishReveal
   ```

2. Instal·lar les dependències:
   ```bash
   pip install playwright beautifulsoup4 requests
   ```

3. Descarregar els binaris del navegador per a Playwright:
   ```bash
   python -m playwright install chromium
   ```

### Ús Bàsic

Col·loca el teu fitxer de correu de mostra (ex. `correo_sospechoso.eml`) al directori arrel i executa l'script:

```bash
python phishreveal.py
```

## Resultats i Generació d'Informes

En finalitzar l'execució, l'eina generarà dos tipus d'evidències:
1. **Captura de pantalla (`evidencia_*.png`):** Una imatge de la web fraudulenta (només si es detecta un risc mitjà o alt).
2. **Informe JSON (`PhishReveal_report.json`):** Un fitxer estructurat preparat per ser ingerit per plataformes SIEM o plataformes de ticketing:

```json
{
    "metadata": {
        "subject": "Avís Urgent: Actualització de credencials Gencat",
        "sender": "suport-IT@domini-fals.com"
    },
    "threat_intelligence": {
        "total_urls_found": 1,
        "findings": [
            {
                "url": "https://sites.google.com/view/portal-empleat-login/inici",
                "domain": "sites.google.com",
                "hosted_on_free_platform": true,
                "has_password_form": true,
                "screenshot_path": "evidencia_sites_google_com.png",
                "risk_level": "ALTO (Posible Robo de Credenciales)"
            }
        ]
    }
}
```