from predict import predict_project

if __name__ == "__main__":
    project_path = r"C:\malicious-npm-detector\College-ERP-master"
    risk, prob = predict_project(project_path, model_type="ensemble")

    print("Risk Level:", risk)
    print("Malicious Probability:", prob)
