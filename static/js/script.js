// Add dynamic form fields for experience and education
document.addEventListener("DOMContentLoaded", function () {
  // Add experience field
  const addExperienceBtn = document.getElementById("addExperience");
  if (addExperienceBtn) {
    addExperienceBtn.addEventListener("click", function () {
      const expCount = document.querySelectorAll(".experience-item").length;
      const expHtml = `
                <div class="experience-item card mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Experience #${expCount + 1}</h6>
                        <button type="button" class="btn btn-sm btn-danger remove-item">Remove</button>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Company</label>
                                    <input type="text" class="form-control" name="exp_company_${expCount}" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Position</label>
                                    <input type="text" class="form-control" name="exp_position_${expCount}" required>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Start Date</label>
                                    <input type="month" class="form-control" name="exp_start_${expCount}" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">End Date</label>
                                    <input type="month" class="form-control" name="exp_end_${expCount}">
                                    <div class="form-check mt-2">
                                        <input class="form-check-input" type="checkbox" id="exp_current_${expCount}" name="exp_current_${expCount}">
                                        <label class="form-check-label" for="exp_current_${expCount}">Current Job</label>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" name="exp_description_${expCount}" rows="3"></textarea>
                        </div>
                    </div>
                </div>
            `;
      document
        .getElementById("experienceContainer")
        .insertAdjacentHTML("beforeend", expHtml);
      document.querySelector('input[name="exp_count"]').value = expCount + 1;

      // Add event listener to the new remove button
      const removeBtn = document.querySelector(
        "#experienceContainer .experience-item:last-child .remove-item"
      );
      removeBtn.addEventListener("click", function () {
        this.closest(".experience-item").remove();
        document.querySelector('input[name="exp_count"]').value =
          document.querySelectorAll(".experience-item").length;
      });

      // Add event listener for current job checkbox
      const currentJobCheckbox = document.getElementById(
        `exp_current_${expCount}`
      );
      currentJobCheckbox.addEventListener("change", function () {
        const endDateInput = this.closest(".col-md-6").querySelector(
          'input[type="month"]'
        );
        endDateInput.disabled = this.checked;
        if (this.checked) {
          endDateInput.value = "";
        }
      });
    });
  }

  // Add education field
  const addEducationBtn = document.getElementById("addEducation");
  if (addEducationBtn) {
    addEducationBtn.addEventListener("click", function () {
      const eduCount = document.querySelectorAll(".education-item").length;
      const eduHtml = `
                <div class="education-item card mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Education #${eduCount + 1}</h6>
                        <button type="button" class="btn btn-sm btn-danger remove-item">Remove</button>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Institution</label>
                                    <input type="text" class="form-control" name="edu_institution_${eduCount}" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Degree</label>
                                    <input type="text" class="form-control" name="edu_degree_${eduCount}" required>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Field of Study</label>
                                    <input type="text" class="form-control" name="edu_field_${eduCount}" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Start Date</label>
                                    <input type="month" class="form-control" name="edu_start_${eduCount}" required>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">End Date</label>
                                    <input type="month" class="form-control" name="edu_end_${eduCount}">
                                    <div class="form-check mt-2">
                                        <input class="form-check-input" type="checkbox" id="edu_current_${eduCount}" name="edu_current_${eduCount}">
                                        <label class="form-check-label" for="edu_current_${eduCount}">Currently Studying</label>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Description</label>
                                    <textarea class="form-control" name="edu_description_${eduCount}" rows="3"></textarea>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
      document
        .getElementById("educationContainer")
        .insertAdjacentHTML("beforeend", eduHtml);
      document.querySelector('input[name="edu_count"]').value = eduCount + 1;

      // Add event listener to the new remove button
      const removeBtn = document.querySelector(
        "#educationContainer .education-item:last-child .remove-item"
      );
      removeBtn.addEventListener("click", function () {
        this.closest(".education-item").remove();
        document.querySelector('input[name="edu_count"]').value =
          document.querySelectorAll(".education-item").length;
      });

      // Add event listener for current study checkbox
      const currentStudyCheckbox = document.getElementById(
        `edu_current_${eduCount}`
      );
      currentStudyCheckbox.addEventListener("change", function () {
        const endDateInput = this.closest(".col-md-6").querySelector(
          'input[type="month"]'
        );
        endDateInput.disabled = this.checked;
        if (this.checked) {
          endDateInput.value = "";
        }
      });
    });
  }

  // Template selection
  const templateOptions = document.querySelectorAll(".resume-template");
  if (templateOptions) {
    templateOptions.forEach((template) => {
      template.addEventListener("click", function () {
        templateOptions.forEach((t) => t.classList.remove("selected"));
        this.classList.add("selected");
        document.querySelector('input[name="template"]').value =
          this.dataset.template;
      });
    });
  }

  // Image preview for resume photo
  const photoInput = document.getElementById("photoInput");
  if (photoInput) {
    photoInput.addEventListener("change", function () {
      const file = this.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
          document.getElementById("photoPreview").src = e.target.result;
        };
        reader.readAsDataURL(file);
      }
    });
  }

  // Initialize tooltips
  const tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });
});
