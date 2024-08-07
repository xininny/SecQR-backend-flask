async function getPrediction(url) {
  try {
      const response = await axios.post(
          "http://127.0.0.1:8080/predict",
          new URLSearchParams({ url: url })
      );
      console.log("Prediction:", response.data.prediction);

      //유형 결과
      document.getElementById("prediction").innerText =
          "Predicted URL type: " + response.data.prediction;

      //url 정보
      const urlInfo = response.data.url_info;
      let urlInfoHtml = `
          <p>Parameter Length: ${urlInfo.parameter_len}</p>
          <p>Having IP Address: ${urlInfo.having_ip_address}</p>
          <p>Protocol: ${urlInfo.protocol}</p>
          <p>Sub Domain: ${urlInfo.sub_domain}</p>
          <p>Abnormal URL: ${urlInfo.abnormal_url}</p>
      `;

      document.getElementById("url-info").innerHTML = urlInfoHtml;
  } catch (error) {
      console.error("Error making request:", error);
      document.getElementById("prediction").innerText =
          "Error fetching prediction";
      document.getElementById("url-info").innerHTML = "";
  }
}