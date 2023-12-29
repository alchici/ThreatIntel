from mitreattack.navlayers import Layer
from mitreattack.navlayers import ToSvg, SVGConfig
import json
from cairosvg import svg2png

def killChainSVG(techniques):
    updateLayer(techniques)

    lay = Layer()
    lay.from_file("layer.json")

    t = ToSvg(domain='enterprise', source='local', resource='enterprise-attack-14.1.json', config=None)
    t.to_svg(layerInit=lay, filepath="demo.svg")

    with open('./demo.svg', 'r') as archivo:
        contenido = archivo.read()

    svg2png(bytestring=contenido,write_to='output.png',scale=2.0)

def updateLayer(techniques):

    with open('./layer.json', 'r') as archivo:
        contenido = archivo.read()

    data = json.loads(contenido)

    data['techniques'] = []

    for technique in techniques:

        item = {'techniqueID': technique, 'score': 100, 'color': '', 'enabled': True, 'metadata': [], 'links': [], 'showSubtechniques': False}

        data['techniques'].append(item)
    
    updated_data = json.dumps(data, indent=4)

    with open('./layer.json', 'w') as archivo_modificado:
        archivo_modificado.write(updated_data)

if __name__ == '__main__':
    killChainSVG(["T1003","T1003","T1111","T1490"])