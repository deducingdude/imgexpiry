# imgexpiry

Tells you which running images your ECR lifecycle policy is about to delete, so a calendar reminder isn't your safety net.

## The problem

We have an ECR registry with a lifecycle policy attached to automatically cleanup images.

The lifecycle policy rules define selection criteria (e.g. tagged with prefix "v") that match images. They also define
conditions for deleting a matched image

- imageCountMoreThan: number of images to keep that match tag criteria.
- sinceImagePushed: number of days to keep an image.

ECR doesn't know what's running, so a policy can delete an image a workload still needs. At GoFundMe, we had some services that were
rarely updated or released. Once or twice, our team received pager duty alerts that these services are down. After investigating,
we found that a node drain, scale-up or eviction had forced a fresh pull but the image was gone, causing `ErrImagePull` / `ImagePullBackOff` error.

Our "solution" was to set up a monthly calendar invite to remind the team to release those services every month. However, this isn't
a good solution because an image can be deleted faster than a month. Also, if there are any changes to lifecycle policy, then the
calendar invite would need to be adjusted.

## What it does

This project replaces the calendar invite with a report/alert that can be integrated into slack or our alerting system (Coralogix).

On execution, it

1. fetches the ecr lifecycle policy so it's always operating on the most current information.
2. fetches the images currently in ecr.
3. evaluates the images against lifecycle policy, predicting when each one will be deleted.
4. compares images in-use against the predictions and flags the ones at risk of being deleted.
5. outputs a report with its findings.  

## How the predictor works and what it cannot know

The predictor determines which images an ECR lifecycle policy will expire.

lifecycle policy rules have a priority. When an image matches two or more rules, the rule with highest priority wins and is applied.

1. Sort rules by priority
2. For each image, find the highest priority rule that matches it. If two rules match an image only the highest priority one applies.
3. If no rules match, the image won't be deleted.
4. If matched rule is `imageCountMoreThan`, then find all images that match the rule and sort them by pushed_at so newest image is first. Then find where the image being considered fits into this ranking. For example, if 5 images match the rule and the image being considered is number 3 and the rule specifies to keep 3, then our image will be deleted after 1 more matching push.
5. If matched rule is `sinceImagePushed`, the image will be deleted at (pushed_at + number of days the rule specifies to keep them).

For `imageCountMoreThan` rules, we only know how many more images will cause our image to be deleted but not when that will be.

This project only supports rules with countType  `imageCountMoreThan` or `sinceImagePushed` and action type `expire`. Other countTypes such as `sinceImagePulled` and action type `transition` produces error exist code 2.

Other gotchas

- ECR may take upto 24 hours to delete an image that matches a rule.
- Lifecycle policy can change 

## Running it and the tests

### setup

python 3.10 or newer is required.

```bash
 python3.12 -m venv .venv
 .venv/bin/pip install -r requirements-dev.txt -e
 .venv/bin/imgexpiry --help
```

### Run tests

```bash
.venv/bin/pytest
```

### Run it locally using fixture data

```bash
.venv/bin/imgexpiry --repo imgexpiry-demo \
--policy-file fixtures/lifecycle-policy.json \
--images-file fixtures/describe-images.json \
--inventory-file fixtures/k8s-items.json
```

### Run it live

Make sure to authenticate with aws first using `aws sso login --profile imgexpiry`

#### live ECR but fixture k8s data

```bash
.venv/bin/imgexpiry --repo imgexpiry-demo \
--profile imgexpiry \
--region us-west-2 \
--inventory-file fixtures/k8s-items.json
```

#### live ECR and k8s cluster

```bash
.venv/bin/imgexpiry --repo imgexpiry-demo --profile imgexpiry --region us-west-2 --context docker-desktop
```

## What's missing and why

## Known flaw
