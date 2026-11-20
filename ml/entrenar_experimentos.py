"""
[OBSOLETO] Script de entrenamiento experimental unificado.

Este archivo se mantiene únicamente como enlace de compatibilidad y delega
el entrenamiento reproducible al pipeline único oficial en `ml/entrenar_cnn.py`
para evitar contradicciones entre artefactos (`ddos_cnn_model.keras`,
`scaler.pkl` y `model_metadata.json`).
"""

import os
import sys

_DIRECTORIO_ML = os.path.dirname(os.path.abspath(__file__))
_DIRECTORIO_BASE = os.path.dirname(_DIRECTORIO_ML)
if _DIRECTORIO_BASE not in sys.path:
    sys.path.insert(0, _DIRECTORIO_BASE)

from ml.entrenar_cnn import principal as entrenar_pipeline_oficial


def principal():
    print(
        "[AVISO] 'ml/entrenar_experimentos.py' está OBSOLETO. "
        "Delegando al pipeline único oficial en 'ml/entrenar_cnn.py'..."
    )
    ruta_csv = sys.argv[1] if len(sys.argv) > 1 else None
    return entrenar_pipeline_oficial(ruta_csv)


if __name__ == "__main__":
    principal()
