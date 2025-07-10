const Razorpay = require('razorpay');
const { CREDIT_PACKS, PLAN_IDS } = require("../constants/paymentConstants");
const crypto = require('crypto');
const Users = require('../model/Users');
const { request } = require('http');

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

const paymentController = {
    createOrder: async (request, response) => {
        try {
            const { credits } = request.body;

            if (!CREDIT_PACKS[credits]) {
                return response.status(400).json({
                    message: 'Invalid credit value'
                });
            }

            const amount = CREDIT_PACKS[credits] * 100; // Convert to paisa

            const order = await razorpay.orders.create({
                amount: amount,
                currency: 'INR',
                receipt: `receipt_${Date.now()}`
            });

            response.json({
                order: order
            });
        } catch (error) {
            console.log(error);
            response.status(500).json({
                message: 'Internal server error'
            });
        }
    },

    verifyOrder: async (request, response) => {
        try {
            const {
                razorpay_order_id, razorpay_payment_id,
                razorpay_signature, credits
            } = request.body;

            const body = razorpay_order_id + "|" + razorpay_payment_id;
            const expectedSignature = crypto
                .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
                .update(body.toString())
                .digest('hex');

            if (expectedSignature !== razorpay_signature) {
                return response.status(400).json({
                    message: 'Signature verification failed'
                });
            }

            const user = await Users.findById({ _id: request.user.id });
            user.credits += Number(credits);
            await user.save();

            response.json({ user: user });
        } catch (error) {
            console.log(error);
            response.status(500).json({
                message: 'Internal server error'
            });
        }
    },
    createSubscription: async (request, response) => {
        try {
            const { plan_name } = request.body;
            if (!PLAN_IDS[plan_name]) {
                return response.status(400).json({
                    message: 'Invalid plan name' // ✅ fixed typo: Inavlid → Invalid
                });
            }

            const plan = PLAN_IDS[plan_name];
            const subscription = await razorpay.subscriptions.create({
                plan_id: plan.id,
                customer_notify: 1,
                total_count: plan.totalBillingCycleCount,
                notes: {
                    userID: request.user.id
                }
            });
            response.json({ subscription: subscription });

        } catch (error) {
            console.log(error);
            response.status(500).json({
                message: 'Internal server error'
            });
        }
    },

    verifySubscription: async (request, response) => {
        try {
            const { subscription_id } = request.body;
            const subscription = await razorpay.subscriptions.fetch(subscription_id);
            const user = await Users.findById({ _id: request.user.id });

            // we will use this entry to prevent user from subscribing again
            // from the UI, while we wait for activated event from razorpay
            user.subscription = {
                id: subscription_id,
                planId: subscription.plan_id,
                status: subscription.status
            };
            await user.save();
            response.json({ user: user });

        } catch (error) {
            console.log(error);
            response.status(500).json({ // ✅ fixed typo: staus → status
                message: 'Internal server error'
            });
        }
    },

    canclesubscriptionn: async (request, response) => { // ✅ left function name unchanged as you requested
        try {
            const { subscription_id } = request.body;
            if (!subscription_id) {
                return response.status(400).json({
                    message: 'Subscription Id is mandatory'
                });
            }

            const data = await razorpay.subscriptions.cancel(subscription_id);
            response.json({ data: data });

        } catch (error) {
            console.log(error);
            response.status(500).json({
                message: 'Internal server error'
            });
        }
    },

    handleWebhookEvent: async (request, response) => { // ✅ fixed requesty → request
        try {
            console.log('Received event');
            const signature = request.headers['x-razorpay-signature']; // ✅ fixed missing "=" and header accessor
            const body = request.body;
            const expectedSignature = crypto
                .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET) // ✅ fixed process.nextTick → process.env
                .update(body)
                .digest('hex');

            if (expectedSignature !== signature) {
                console.log('Invalid signature')
                return response.status(400).send('Invalid Signature');
            }

            const payload = JSON.parse(body);
            console.log(JSON.stringify(payload, null, 2)); // ✅ fixed 0 → null for pretty print
            const event = payload.event;
            const subscriptionData = payload.payload.subscription.entity;
            const razorpaySubscriptionId = subscriptionData.id;
            const userId = subscriptionData.notes ? subscriptionData.notes.userId : null; // ✅ fixed logic for userId

            if (!userId) {
                console.log('UserId not found in notes');
                return response.status(400).send('UserId not found in notes');
            }

            let newStatus = '';
            switch (event) {
                case 'subscription.activated':
                    newStatus = 'active';
                    break;
                case 'subscription.pendinng':
                    newStatus = 'pending';
                    break;
                case 'subscription.cancelled':
                    newStatus = 'cancelled';
                    break;
                case 'subscription.completed':
                    newStatus = 'completed';
                    break;
                default:
                    console.log('Unhandled event : ', event);
                    return response.status(200).send('Unhandled event');
            }

            const user = await Users.findOneAndUpdate(
                { _id: userId },
                {
                    $set: {
                        'Subscription.id': razorpaySubscriptionId,
                        'Subscription.planId': subscriptionData.plan_id,
                        'Subscription.status': newStatus,
                        'Subscription:start': subscriptionData.start_at
                            ? new Date(subscriptionData.start_at * 1000)
                            : null,
                        'Subscription:end': subscriptionData.end_at
                            ? new Date(subscriptionData.end_at * 1000)
                            : null,
                        'Subscription:lastBillDate': subscriptionData.current_start
                            ? new Date(subscriptionData.current_start * 1000)
                            : null,
                        'Subscription:BillnextDate': subscriptionData.current_end
                            ? new Date(subscriptionData.current_end * 1000)
                            : null,
                        'subscription:paymentsMade': subscriptionData.paid_count,
                        'subscription:paymentsRemaining': subscriptionData.remaining_count,

                    }
                },
                { new: true }
            );

            if (!user) {
                console.log('USer is not valid');
                return response.status(400).send('UserId is not valid');
            }
            console.log(`Updated subscription status for user ${userId} to ${newStatus}`);
            return response.status(200).send(`Event processed for user:${userId}`);


        } catch (error) {
            console.log(error);
            response.status(500).json({
                message: 'Internal server error'
            });
        }
    }

};

module.exports = paymentController;