from flask import Flask,render_template,request
import requests
from email.parser import HeaderParser
import time
import dateutil.parser
from datetime import datetime
import re
import pygal
from pygal.style import Style
from IPy import IP
import geoip2.database
import json

app=Flask(__name__)
reader = geoip2.database.Reader(
    '%s/data/GeoLite2-Country.mmdb' % app.static_folder)

#route for landing page
@app.route('/')
def index1():
    return render_template('index.html')


#for mail header
@app.context_processor
def utility_processor():
    def getCountryForIP(line):
        ipv4_address = re.compile(r"""
            \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)
        ip = ipv4_address.findall(line)
        if ip:
            ip = ip[0]  # take the 1st ip and ignore the rest
            if IP(ip).iptype() == 'PUBLIC':
                r = reader.country(ip).country
                if r.iso_code and r.name:
                    return {
                        'iso_code': r.iso_code.lower(),
                        'country_name': r.name
                    }
    return dict(country=getCountryForIP)


def dateParser(line):
    try:
        r = dateutil.parser.parse(line, fuzzy=True)

   
    except ValueError:
        r = re.findall('^(.*?)\s*(?:\(|utc)', line, re.I)
        if r:
            r = dateutil.parser.parse(r[0])
    return r

def getHeaderVal(h, data, rex='\s*(.*?)\n\S+:\s'):
    r = re.findall('%s:%s' % (h, rex), data, re.X | re.DOTALL | re.I)
    if r:
        return r[0].strip()
    else:
        return None


@app.context_processor
def utility_processor():
    def duration(seconds, _maxweeks=99999999999):
        return ', '.join(
            '%d %s' % (num, unit)
            for num, unit in zip([
                (seconds // d) % m
                for d, m in (
                    (604800, _maxweeks),
                    (86400, 7), (3600, 24),
                    (60, 60), (1, 60))
            ], ['wk', 'd', 'hr', 'min', 'sec'])
            if num
        )
    return dict(duration=duration)
###end


@app.route('/scan',methods=["GET","POST"])
def scan():
    results = []
    if request.method == "POST":
        url_to_check = request.form.get("url")
        
        
        url1 = "https://www.virustotal.com/api/v3/urls"
        headers = {
            'x-apikey': '5066c4e5f08568d5eeace327b4f367ea8ce2a7dd94d17d8df760731ab9803ccb'
        }

        data = {
            'url': url_to_check
        }
        response = requests.post(url1, headers=headers, data=data)
        
        if response.status_code == 200:
            data1 = response.json()
            urlres = data1['data']['links']['self']
            urllist = urlres.split('-')
            url2 = 'https://www.virustotal.com/api/v3/urls/' + urllist[1]

            res2 = requests.get(url2, headers=headers)
            res = res2.json()

            # Extract the relevant information
            for engine, details in res['data']['attributes']['last_analysis_results'].items():
                engine_name = details['engine_name']
                category = details['category']
                result = details['result']
                color_class = "green"  # default color

                if result in ["malicious", "harmful", "undetected", "phishing","unrated","not recommended"]:
                    color_class = "red"
                if result in ["unrated"]:
                    color_class="grey"
                
                results.append({
                    'engine_name': engine_name,
                    'category': category,
                    'result': result,
                    'color_class': color_class
                })
        else:
            return "Error retrieving data from VirusTotal", 500
    return render_template('scan.html',results=results)









### END OF SCAN

@app.route('/contacts')
def contacts():
    return render_template('contact.html')

#1. scanning using virusttal API
@app.route('/scan')
def exploit():

    return render_template('scan.html')


#mail header scanner
##
###
####
@app.route('/mha', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        mail_data = request.form['headers'].strip()
        r = {}
        n = HeaderParser().parsestr(mail_data)
        graph = []
        received = n.get_all('Received')
        if received:
            received = [i for i in received if ('from' in i or 'by' in i)]
        else:
            received = re.findall(
                'Received:\s*(.*?)\n\S+:\s+', mail_data, re.X | re.DOTALL | re.I)
        c = len(received)
        for i in range(len(received)):
            if ';' in received[i]:
                line = received[i].split(';')
            else:
                line = received[i].split('\r\n')
            line = list(map(str.strip, line))
            line = [x.replace('\r\n', ' ') for x in line]
            try:
                if ';' in received[i + 1]:
                    next_line = received[i + 1].split(';')
                else:
                    next_line = received[i + 1].split('\r\n')
                next_line = list(map(str.strip, next_line))
                next_line = [x.replace('\r\n', '') for x in next_line]
            except IndexError:
                next_line = None

            org_time = dateParser(line[-1])
            if not next_line:
                next_time = org_time
            else:
                next_time = dateParser(next_line[-1])

            if line[0].startswith('from'):
                data = re.findall(
                    """
                    from\s+
                    (.*?)\s+
                    by(.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s|$
                    )""", line[0], re.DOTALL | re.X)
            else:
                data = re.findall(
                    """
                    ()by
                    (.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s
                    )""", line[0], re.DOTALL | re.X)

            delay = (org_time - next_time).seconds
            if delay < 0:
                delay = 0

            try:
                ftime = org_time.utctimetuple()
                ftime = time.strftime('%m/%d/%Y %I:%M:%S %p', ftime)
                r[c] = {
                    'Timestmp': org_time,
                    'Time': ftime,
                    'Delay': delay,
                    'Direction': [x.replace('\n', ' ') for x in list(map(str.strip, data[0]))]
                }
                c -= 1
            except IndexError:
                pass

        for i in list(r.values()):
            if i['Direction'][0]:
                graph.append(["From: %s" % i['Direction'][0], i['Delay']])
            else:
                graph.append(["By: %s" % i['Direction'][1], i['Delay']])

        totalDelay = sum([x['Delay'] for x in list(r.values())])
        fTotalDelay = utility_processor()['duration'](totalDelay)
        delayed = True if totalDelay else False

        custom_style = Style(
            background='transparent',
            plot_background='transparent',
            font_family='googlefont:Open Sans',
            # title_font_size=12,
        )
        line_chart = pygal.HorizontalBar(
            style=custom_style, height=250, legend_at_bottom=True,
            tooltip_border_radius=10)
        line_chart.tooltip_fancy_mode = False
        line_chart.title = 'Total Delay is: %s' % fTotalDelay
        line_chart.x_title = 'Delay in seconds.'
        for i in graph:
            line_chart.add(i[0], i[1])
        chart = line_chart.render(is_unicode=True)

        summary = {
            'From': n.get('From') or getHeaderVal('from', mail_data),
            'To': n.get('to') or getHeaderVal('to', mail_data),
            'Cc': n.get('cc') or getHeaderVal('cc', mail_data),
            'Subject': n.get('Subject') or getHeaderVal('Subject', mail_data),
            'MessageID': n.get('Message-ID') or getHeaderVal('Message-ID', mail_data),
            'Date': n.get('Date') or getHeaderVal('Date', mail_data),
        }

        security_headers = ['Received-SPF', 'Authentication-Results',
                            'DKIM-Signature', 'ARC-Authentication-Results']
        return render_template(
            'mailha.html', data=r, delayed=delayed, summary=summary,
            n=n, chart=chart, security_headers=security_headers)
    else:
        return render_template('mailha.html')
#end mail header




@app.route('/login')
def login():
    return render_template('login.html')




## Exploiter
@app.route('/exploiter')
def exploiter():
    #product_ver=request.form['pro_version']
    return render_template('exploit.html')


@app.route('/get_cves', methods=['GET','POST'])
def get_cves():
    cve_info = []
    
    if request.method == "POST":
        product_name = request.form["product_name"]
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product_name}"
        
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract the relevant information
            for vulnerability in data['vulnerabilities']:
                cve_id = vulnerability['cve']['id']
                descriptions = vulnerability['cve'].get('descriptions', [])
                
                for description in descriptions:
                    if description['lang'] == "en":  
                        cve_info.append({
                            'id': cve_id,
                            'description': description['value']
                        })
        else:
            cve_info.append({'id': 'Error', 'description': 'Failed to retrieve data'})

    return render_template("exploit.html", cve_info=cve_info)


## END CODE FOR EXPLOITER
if __name__=='__main__':
    app.run()
